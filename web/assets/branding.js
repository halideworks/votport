// Recipient-facing tenant branding shared by the request and download pages.
// VOTPORT PROPRIETARY LICENSE.

/// Applies the branding object from link/grant metadata: heading, accent
/// color, and logo. Absent branding leaves the page exactly as shipped.
export function applyBranding(branding, logoUrl) {
  if (!branding) return;
  if (branding.name) {
    document.getElementById('title').textContent = branding.name;
  }
  if (/^#[0-9a-fA-F]{6}$/.test(branding.color || '')) {
    document.documentElement.style.setProperty('--progress', branding.color);
  }
  if (branding.has_logo && !document.querySelector('.masthead .brand-logo')) {
    const logo = document.createElement('img');
    logo.src = logoUrl;
    logo.alt = '';
    logo.className = 'brand-logo';
    document.querySelector('.masthead').prepend(logo);
  }
}
