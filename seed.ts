import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();
const products = [
  ["The Regent Runner", "the-regent-runner", "MV-SHOE-001", "Sculpted everyday runner with effortless presence.", 185000, 220000, 24, true, true],
  ["The Verona Loafer", "the-verona-loafer", "MV-SHOE-002", "Polished leather, considered down to the last stitch.", 245000, null, 18, true, false],
  ["The Muse Heel", "the-muse-heel", "MV-SHOE-003", "A confident silhouette for after-dark occasions.", 210000, 250000, 3, true, false],
  ["The Meridian", "the-meridian", "MV-WATCH-001", "A quiet statement in brushed steel and midnight black.", 390000, null, 12, true, true],
  ["The Axis Chrono", "the-axis-chrono", "MV-WATCH-002", "Precision and character for the modern daily ritual.", 325000, null, 16, true, true],
  ["The Court Classic", "the-court-classic", "MV-SHOE-004", "A considered low-top with a clean, timeless line.", 165000, null, 20, true, false],
  ["The Atelier", "the-atelier", "MV-WATCH-003", "Architectural proportions and an exceptional finish.", 510000, null, 0, true, false],
  ["The Porter Slide", "the-porter-slide", "MV-SHOE-005", "The easy, elevated essential for off-duty days.", 120000, 145000, 5, true, false]
] as const;

async function main(): Promise<void> {
  for (const [name, slug, sku, description, priceMinor, discountMinor, stockQuantity, featured, bestSeller] of products) {
    await prisma.product.upsert({
      where: { sku },
      update: { name, slug, description, priceMinor: priceMinor * 100, discountMinor: discountMinor ? discountMinor * 100 : null, stockQuantity, featured, bestSeller, active: true },
      create: { name, slug, sku, description, priceMinor: priceMinor * 100, discountMinor: discountMinor ? discountMinor * 100 : null, stockQuantity, featured, bestSeller, newArrival: sku.endsWith("001") }
    });
  }
}

main().finally(() => prisma.$disconnect());
