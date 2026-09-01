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
    // The accent colors the progress meter and focus rings, and becomes the
    // primary button face with whichever text color reads on it.
    document.documentElement.style.setProperty('--progress', branding.color);
    document.documentElement.style.setProperty('--btn-bg', branding.color);
    document.documentElement.style.setProperty('--btn-text', textOn(branding.color));
  }
  if (branding.has_logo && !document.querySelector('.masthead .brand-logo')) {
    const logo = document.createElement('img');
    logo.src = logoUrl;
    logo.alt = '';
    logo.className = 'brand-logo';
    document.querySelector('.masthead').prepend(logo);
  }
}

/// Whichever of the palette's dark and light text colors has the higher WCAG
/// contrast ratio against a #rrggbb background.
function textOn(hex) {
  const channel = (offset) => {
    const value = parseInt(hex.slice(offset, offset + 2), 16) / 255;
    return value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  };
  const luminance = 0.2126 * channel(1) + 0.7152 * channel(3) + 0.0722 * channel(5);
  const contrast = (other) =>
    (Math.max(luminance, other) + 0.05) / (Math.min(luminance, other) + 0.05);
  // Relative luminance of #0b141e and #f8fafc.
  return contrast(0.0064) >= contrast(0.949) ? '#0b141e' : '#f8fafc';
}
