import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const styles = readFileSync(join(repository, "frontend", "src", "styles.css"), "utf8");
const startup = readFileSync(join(repository, "frontend", "public", "startup-error.html"), "utf8");

const token = (name) => {
  const match = styles.match(new RegExp(`--${name}:\\s*(#[0-9A-Fa-f]{6})\\s*;`));
  if (!match) throw new Error(`Missing solid color token --${name}.`);
  return match[1];
};

const startupColor = (property, value) => {
  if (!startup.includes(`${property}: ${value};`)) {
    throw new Error(`Startup surface no longer contains ${property}: ${value}.`);
  }
  return value;
};

const focusAlphaMatch = styles.match(
  /\.sidebar-nav a:focus-visible\s*\{[^}]*rgba\(156,\s*196,\s*255,\s*([0-9.]+)\)/s,
);
if (!focusAlphaMatch) throw new Error("Sidebar focus-ring alpha could not be measured.");

const colors = {
  page: token("color-page"),
  sidebar: token("color-sidebar"),
  surface: token("color-surface"),
  elevated: token("color-surface-elevated"),
  inset: token("color-surface-inset"),
  hover: token("color-surface-hover"),
  selected: token("color-surface-selected"),
  primary: token("color-text-primary"),
  secondary: token("color-text-secondary"),
  muted: token("color-text-muted"),
  disabled: token("color-text-disabled"),
  accent: token("color-accent"),
  focus: token("color-focus-ring"),
  success: token("color-success"),
  warning: token("color-warning"),
  danger: token("color-danger"),
  info: token("color-info"),
};

const samples = [
  ["body text on page", colors.primary, colors.page, 4.5],
  ["secondary text on surface", colors.secondary, colors.surface, 4.5],
  ["muted text on hover surface", colors.muted, colors.hover, 4.5],
  ["link text on page", colors.accent, colors.page, 4.5],
  ["primary button text", colors.page, colors.accent, 4.5],
  ["secondary button text", colors.primary, colors.elevated, 4.5],
  ["form value on inset", colors.primary, colors.inset, 4.5],
  ["disabled control text", colors.disabled, colors.elevated, 4.5],
  ["selected-card text", colors.primary, colors.selected, 4.5],
  ["dialog text", colors.primary, colors.elevated, 4.5],
  ["success text on surface", colors.success, colors.surface, 4.5],
  ["warning text on surface", colors.warning, colors.surface, 4.5],
  ["error text on surface", colors.danger, colors.surface, 4.5],
  ["information text on surface", colors.info, colors.surface, 4.5],
  ["focus ring on page", colors.focus, colors.page, 3],
  [
    "sidebar focus ring after alpha composition",
    blend(colors.focus, colors.sidebar, Number(focusAlphaMatch[1])),
    colors.sidebar,
    3,
  ],
  [
    "startup error text",
    startupColor("color", "#162033"),
    startupColor("background", "#ffffff"),
    4.5,
  ],
];

const failures = [];
for (const [label, foreground, background, threshold] of samples) {
  const ratio = contrast(foreground, background);
  process.stdout.write(`${label}: ${ratio.toFixed(2)}:1 (minimum ${threshold.toFixed(1)}:1)\n`);
  if (ratio + Number.EPSILON < threshold) failures.push(`${label} is ${ratio.toFixed(2)}:1`);
}

if (!styles.includes("max-height: calc(100vh - 48px);") || !styles.includes("overflow-y: auto;")) {
  failures.push("Modal viewport containment rules are missing.");
}

if (failures.length) {
  throw new Error(`G052 accessibility validation failed:\n- ${failures.join("\n- ")}`);
}

process.stdout.write(`Validated ${samples.length} representative contrast pairs and modal viewport containment.\n`);

function contrast(foreground, background) {
  const lighter = Math.max(luminance(foreground), luminance(background));
  const darker = Math.min(luminance(foreground), luminance(background));
  return (lighter + 0.05) / (darker + 0.05);
}

function luminance(color) {
  const [red, green, blue] = parseHex(color).map((channel) => {
    const value = channel / 255;
    return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  });
  return (0.2126 * red) + (0.7152 * green) + (0.0722 * blue);
}

function blend(foreground, background, alpha) {
  const front = parseHex(foreground);
  const back = parseHex(background);
  return `#${front.map((channel, index) => (
    Math.round((channel * alpha) + (back[index] * (1 - alpha))).toString(16).padStart(2, "0")
  )).join("")}`;
}

function parseHex(color) {
  const value = color.replace("#", "");
  if (!/^[0-9a-f]{6}$/i.test(value)) throw new Error(`Expected a six-digit hex color, found ${color}.`);
  return [0, 2, 4].map((offset) => Number.parseInt(value.slice(offset, offset + 2), 16));
}
