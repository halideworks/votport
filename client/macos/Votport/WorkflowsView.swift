import SwiftUI
import AppKit
import VotportCore

struct WorkflowsView: View {
    @EnvironmentObject private var port: PortStore
    @State private var projects: [WorkflowProject] = []
    @State private var jobs: [WorkflowJob] = []
    @State private var records: [VerificationRecord] = []
    @State private var projectID = ""
    @State private var label = ""
    @State private var days = 7
    @State private var metadata: [String: String] = [:]
    @State private var recipients: Set<String> = []
    @State private var operation = UUID().uuidString
    @State private var cursor: String?
    @State private var busy = false
    @State private var problem: String?
    @State private var confirmation: Confirmation?

    private struct Confirmation: Identifiable {
        let id: String
        let action: String
        let manifest: String?
    }

    private var project: WorkflowProject? { projects.first { $0.id == projectID } }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Delivery workflows").font(Type.sans(24, .semibold, relativeTo: .title))
                Button("Refresh") { refresh() }.disabled(busy)
                if let problem { Text(problem).foregroundStyle(Tokens.danger).textSelection(.enabled) }
                if port.signedIn {
                    if let base = port.port?.base, let url = URL(string: base + "/deliver#workflows") {
                        Link("Project rules, schedules, storage and events", destination: url)
                    }
                    GroupBox("Create a delivery") {
                        VStack(alignment: .leading, spacing: 10) {
                            Picker("Project", selection: $projectID) {
                                Text("Choose a project").tag("")
                                ForEach(projects, id: \.id) { Text($0.label).tag($0.id) }
                            }
                            TextField("Delivery label", text: $label).textFieldStyle(.roundedBorder)
                            Stepper("Expires after \(days) days", value: $days, in: 1...365)
                            if let project {
                                Text("\(project.directory) · \(project.requireApproval ? "Approval required" : "No approval required")").font(Type.caption)
                                ForEach(project.requiredMetadata, id: \.self) { key in
                                    TextField(key, text: Binding(get: { metadata[key] ?? "" }, set: { metadata[key] = $0 })).textFieldStyle(.roundedBorder)
                                }
                                ForEach(project.recipients, id: \.holder) { recipient in
                                    Toggle("\(recipient.email) (\(recipient.holder.prefix(12))…)", isOn: Binding(get: { recipients.contains(recipient.holder) }, set: { if $0 { recipients.insert(recipient.holder) } else { recipients.remove(recipient.holder) } }))
                                }
                            }
                            HStack {
                                Button("Queue delivery") { create() }
                                Button("Start a separate delivery") { operation = UUID().uuidString; problem = nil }
                            }.disabled(busy || project == nil || label.trimmingCharacters(in: .whitespaces).isEmpty)
                        }.padding(8)
                    }
                    Text("Jobs").font(Type.sans(18, .semibold, relativeTo: .headline))
                    ForEach(jobs, id: \.id) { job in
                        GroupBox {
                            VStack(alignment: .leading, spacing: 8) {
                                Text("\(job.label) · \(job.project) · \(human(job.state))")
                                if let manifest = job.manifest { Text("Manifest: \(manifest)").font(Type.monoBody).textSelection(.enabled) }
                                if let error = job.error { Text(error).foregroundStyle(Tokens.danger) }
                                HStack {
                                    if let url = job.url { Button("Copy download link") { copy(url) } }
                                    if job.state == "awaiting_approval" { Button("Approve this manifest") { confirmation = Confirmation(id: job.id, action: "approve", manifest: job.manifest) } }
                                    if job.state == "failed" { Button("Retry job") { change(job.id, "retry", job.manifest) } }
                                    if !["cancelled", "retired", "retiring"].contains(job.state) { Button("Cancel job") { confirmation = Confirmation(id: job.id, action: "cancel", manifest: job.manifest) } }
                                }.disabled(busy)
                            }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
                        }
                    }
                    if cursor != nil { Button("Load more jobs") { loadJobs(more: true) }.disabled(busy) }
                }
                Text("Recipient verification and acceptance").font(Type.sans(18, .semibold, relativeTo: .headline))
                Text("Accept a delivery only after reviewing the verified files. Acceptance signs the exact manifest shown here.")
                HStack {
                    Button("Copy this device's public key") { run({ try recipientDeviceKey() }) { copy($0) } }
                    Button("Retry pending reports") { run({ _ = retryEvidence(); return deliveryVerifications() }) { records = $0 } }
                }.disabled(busy)
                if records.isEmpty { Text("Verified deliveries received on this device will appear here.").foregroundStyle(Tokens.muted) }
                ForEach(records, id: \.id) { record in
                    GroupBox {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("\(record.server) · Delivery \(record.grantId)")
                            Text("Manifest: \(record.manifest)").font(Type.monoBody).textSelection(.enabled)
                            Text("Verification: \(human(record.verificationStatus)) · Acceptance: \(human(record.acceptanceStatus))")
                            if record.acceptanceStatus == "not_accepted" {
                                Button("Accept verified delivery") { confirmation = Confirmation(id: record.id, action: "accept", manifest: record.manifest) }.disabled(busy)
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
                    }
                }
            }.padding(24).frame(maxWidth: .infinity, alignment: .leading)
        }
        .onAppear { refresh() }
        .onChange(of: projectID) { _, _ in metadata = [:]; recipients = [] }
        .alert("Confirm delivery action", isPresented: Binding(get: { confirmation != nil }, set: { if !$0 { confirmation = nil } }), presenting: confirmation) { action in
            Button(action.action == "cancel" ? "Cancel job" : action.action == "accept" ? "Accept" : "Approve") {
                if action.action == "accept" {
                    run({ _ = try acceptDelivery(verificationId: action.id); return deliveryVerifications() }) { records = $0 }
                } else { change(action.id, action.action, action.manifest) }
                confirmation = nil
            }
            Button("Back", role: .cancel) { confirmation = nil }
        } message: { action in
            Text(action.action == "cancel" ? "Stop subsequent downloads for this job?" : "Confirm you reviewed and \(action.action) manifest \(action.manifest ?? "")?")
        }
    }

    private func human(_ value: String) -> String { value.replacingOccurrences(of: "_", with: " ") }
    private func copy(_ value: String) { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(value, forType: .string) }
    private func run<T: Sendable>(_ work: @escaping @Sendable () throws -> T, then: @escaping @MainActor (T) -> Void) {
        guard !busy else { return }
        busy = true; problem = nil
        Thread {
            let result = Result { try work() }
            DispatchQueue.main.async {
                busy = false
                switch result {
                case .success(let value): then(value)
                case .failure(let error): problem = String(describing: error)
                }
            }
        }.start()
    }
    private func refresh() {
        let signed = port.signedIn
        run({ deliveryVerifications() }) { local in
            records = local
            guard signed else { projects = []; jobs = []; cursor = nil; return }
            run({ (try workflowProjects(), try workflowJobs(after: nil)) }) { result in
                projects = result.0; jobs = result.1.jobs; cursor = result.1.next
                if !projects.contains(where: { $0.id == projectID }) { projectID = projects.first?.id ?? "" }
            }
        }
    }
    private func loadJobs(more: Bool) {
        let after = more ? cursor : nil
        run({ try workflowJobs(after: after) }) { page in jobs = more ? jobs + page.jobs : page.jobs; cursor = page.next }
    }
    private func create() {
        guard let project else { return }
        if project.requiredMetadata.contains(where: { (metadata[$0] ?? "").trimmingCharacters(in: .whitespaces).isEmpty }) { problem = "Complete the required metadata fields."; return }
        let spec = WorkflowJobSpec(operationId: operation, projectId: project.id, label: label.trimmingCharacters(in: .whitespaces), metadata: metadata, recipients: recipients.sorted(), expiresDays: UInt64(days), notBefore: nil, deadline: nil)
        run({ _ = try createWorkflowJob(spec: spec); return try workflowJobs(after: nil) }) { page in jobs = page.jobs; cursor = page.next }
    }
    private func change(_ id: String, _ action: String, _ manifest: String?) {
        run({ _ = try changeWorkflowJob(id: id, action: action, manifest: manifest); return try workflowJobs(after: nil) }) { page in jobs = page.jobs; cursor = page.next }
    }
}
