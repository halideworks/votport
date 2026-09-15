using System.Web;

namespace Votport;

internal static class WebLinkParser
{
    internal static (string kind, string link)? Parse(Uri url)
    {
        if (url.Scheme != "votport") return null;
        var kind = url.Host;
        if (kind != "r" && kind != "s") return null;
        var path = url.AbsolutePath;
        if (!path.StartsWith('/')) return null;
        var token = path[1..];
        if (token.Length == 0 || token.Contains('/') || token.Contains('\\')) return null;
        var decodedToken = Uri.UnescapeDataString(token);
        if (decodedToken.Contains('/') || decodedToken.Contains('\\')) return null;
        var query = HttpUtility.ParseQueryString(url.Query);
        var origin = query["base"];
        if (origin is null || !Uri.TryCreate(origin, UriKind.Absolute, out var parsed)) return null;
        if (parsed.Scheme != "https" && parsed.Scheme != "http") return null;
        if (parsed.Host.Length == 0 || (parsed.AbsolutePath != "" && parsed.AbsolutePath != "/")
            || parsed.Query.Length != 0 || parsed.Fragment.Length != 0 || parsed.UserInfo.Length != 0) return null;
        return (kind, $"{origin.TrimEnd('/')}/{kind}/{token}");
    }
}
