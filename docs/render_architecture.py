"""Render the minimal architecture visual as a PNG."""

from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent
image = Image.new("RGB", (1400, 720), "#07111f")
draw = ImageDraw.Draw(image)


def font(size: int, bold: bool = False):
    try:
        return ImageFont.truetype("DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf", size)
    except OSError:
        return ImageFont.load_default()


def centered(text: str, x: int, y: int, size: int, color: str, bold: bool = False):
    selected = font(size, bold)
    box = draw.textbbox((0, 0), text, font=selected)
    draw.text((x - (box[2] - box[0]) / 2, y), text, fill=color, font=selected)


centered("Cloud Secret Exposure Guard", 700, 55, 34, "#f8fafc", True)
centered("Redaction-first evidence before credential remediation", 700, 105, 18, "#94a3b8")

nodes = [
    (70, "Config bundle", ["CI artifacts", "IaC + app settings"], "#a78bfa"),
    (405, "Validate + scan", ["Deterministic rules", "Placeholder handling"], "#60a5fa"),
    (740, "Redacted report", ["Severity + location", "No secret values"], "#2dd4bf"),
    (1075, "Human response", ["Rotate + revoke", "Clean history safely"], "#f59e0b"),
]

for left, title, details, outline in nodes:
    draw.rounded_rectangle((left, 245, left + 260, 415), radius=20, fill="#10243e", outline=outline, width=3)
    centered(title, left + 130, 285, 22, "#f8fafc", True)
    centered(details[0], left + 130, 335, 17, "#94a3b8")
    centered(details[1], left + 130, 368, 17, "#94a3b8")

for start in (330, 665, 1000):
    end = start + 75
    draw.line((start, 330, end, 330), fill="#38bdf8", width=5)
    draw.polygon(((end, 330), (end - 21, 317), (end - 21, 343)), fill="#38bdf8")

draw.rounded_rectangle((250, 515, 1150, 587), radius=16, fill="#0b1d33", outline="#334155", width=2)
centered("No secret values in reports · No automatic rotation · Human approval retained", 700, 540, 18, "#cbd5e1")
image.save(ROOT / "architecture.png", "PNG", optimize=True)

