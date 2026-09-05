import "dotenv/config";
import crypto from "node:crypto";
import path from "node:path";
import fs from "node:fs/promises";
import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import helmet from "helmet";
import bcrypt from "bcryptjs";
import { PrismaClient, UserRole } from "@prisma/client";
import { z } from "zod";

const prisma = new PrismaClient();
const app = express();
const port = Number(process.env.PORT ?? 4000);
const cookieName = process.env.SESSION_COOKIE_NAME ?? "mv_session";
const sessionDays = 30;

app.use(helmet());
const allowedOrigin = process.env.FRONTEND_ORIGIN ?? "http://localhost:3000";
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || origin === allowedOrigin || (process.env.NODE_ENV !== "production" && (origin === "null" || origin.startsWith("http://localhost:")))) {
      callback(null, true);
      return;
    }
    callback(new Error("Origin is not allowed"));
  },
  credentials: true
}));
app.use(express.json({ limit: "100kb" }));
app.use(express.static(path.resolve(__dirname, "../../")));
app.use("/uploads", express.static(path.resolve(__dirname, "../../uploads")));

const authSchema = z.object({
  email: z.string().trim().email().max(254),
  password: z.string().min(8).max(128)
});
const profileSchema = z.object({
  name: z.string().trim().min(1).max(100).optional(),
  phone: z.string().trim().max(30).optional()
});
const passwordSchema = z.object({
  currentPassword: z.string().min(8).max(128),
  newPassword: z.string().min(8).max(128)
});
const resetSchema = z.object({
  token: z.string().min(32).max(128),
  password: z.string().min(8).max(128)
});
const verificationSchema = z.object({ token: z.string().min(32).max(128) });
const paymentSchema = z.object({
  provider: z.enum(["paystack", "flutterwave"]),
  email: z.string().trim().email().max(254),
  currency: z.enum(["NGN", "GHS"]),
  items: z.array(z.object({ sku: z.string().min(1), quantity: z.number().int().positive().max(20) })).min(1).max(50)
});
const productInputSchema = z.object({
  name: z.string().trim().min(1).max(160),
  slug: z.string().trim().min(1).max(180).regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/),
  sku: z.string().trim().min(1).max(80),
  description: z.string().trim().min(1).max(5000),
  shortDescription: z.string().trim().max(500).optional().nullable(),
  category: z.string().trim().min(1).max(80),
  gender: z.string().trim().max(40).optional().nullable(),
  priceMinor: z.number().int().nonnegative(),
  discountMinor: z.number().int().nonnegative().optional().nullable(),
  costMinor: z.number().int().nonnegative().optional().nullable(),
  images: z.array(z.object({ url: z.string().url().max(2000), alt: z.string().trim().max(160) })).max(20).default([]),
  sizes: z.array(z.string().trim().min(1).max(40)).max(100).default([]),
  colours: z.array(z.string().trim().min(1).max(40)).max(100).default([]),
  variants: z.any().optional().nullable(),
  stockQuantity: z.number().int().nonnegative(),
  lowStockAt: z.number().int().nonnegative(),
  active: z.boolean(),
  featured: z.boolean(),
  bestSeller: z.boolean(),
  newArrival: z.boolean(),
  seoTitle: z.string().trim().max(160).optional().nullable(),
  seoDescription: z.string().trim().max(320).optional().nullable()
});
const orderStatusSchema = z.object({
  status: z.enum(["PENDING", "PAID", "PROCESSING", "PACKED", "SHIPPED", "OUT_FOR_DELIVERY", "DELIVERED", "CANCELLED", "RETURNED", "REFUNDED"]),
  trackingNumber: z.string().trim().max(120).optional().nullable(),
  carrier: z.string().trim().max(120).optional().nullable()
});

function cookieValue(request: Request): string | undefined {
  const header = request.headers.cookie;
  if (!header) return undefined;
  return header.split(";").map(value => value.trim()).find(value => value.startsWith(`${cookieName}=`))?.slice(cookieName.length + 1);
}

function setSessionCookie(response: Response, sessionId: string, expires: Date): void {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  response.setHeader("Set-Cookie", `${cookieName}=${sessionId}; HttpOnly; Path=/; SameSite=Lax; Expires=${expires.toUTCString()}${secure}`);
}

function clearSessionCookie(response: Response): void {
  response.setHeader("Set-Cookie", `${cookieName}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0`);
}

async function createSession(userId: string, response: Response): Promise<void> {
  const expiresAt = new Date(Date.now() + sessionDays * 24 * 60 * 60 * 1000);
  const sessionId = crypto.randomBytes(32).toString("hex");
  await prisma.session.create({ data: { id: sessionId, userId, expiresAt } });
  setSessionCookie(response, sessionId, expiresAt);
}

type AuthRequest = Request & { user?: { id: string; role: UserRole } };
async function requireAuth(request: AuthRequest, response: Response, next: NextFunction): Promise<void> {
  const sessionId = cookieValue(request);
  if (!sessionId) { response.status(401).json({ error: "Authentication required" }); return; }
  const session = await prisma.session.findUnique({ where: { id: sessionId }, include: { user: { select: { id: true, role: true } } } });
  if (!session || session.expiresAt <= new Date()) {
    if (session) await prisma.session.delete({ where: { id: session.id } });
    clearSessionCookie(response);
    response.status(401).json({ error: "Session expired" });
    return;
  }
  request.user = session.user;
  next();
}

async function requireAdmin(request: AuthRequest, response: Response, next: NextFunction): Promise<void> {
  await requireAuth(request, response, () => {
    if (request.user?.role !== UserRole.ADMIN) {
      response.status(403).json({ error: "Administrator access required" });
      return;
    }
    next();
  });
}

app.get("/api/health", (_request, response) => response.json({ ok: true }));

app.get("/api/admin/overview", requireAdmin, async (_request, response, next) => {
  try {
    const [revenue, totalOrders, totalCustomers, totalProducts, pendingOrders, completedOrders, lowStockProducts, recentOrders, topSellingProducts] = await Promise.all([
      prisma.order.aggregate({ _sum: { totalMinor: true }, where: { status: { notIn: ["CANCELLED", "REFUNDED"] } } }),
      prisma.order.count(),
      prisma.user.count({ where: { role: UserRole.CUSTOMER } }),
      prisma.product.count({ where: { active: true } }),
      prisma.order.count({ where: { status: { in: ["PENDING", "PROCESSING", "PACKED"] } } }),
      prisma.order.count({ where: { status: "DELIVERED" } }),
      prisma.product.findMany({ where: { active: true, stockQuantity: { lte: 5 } }, orderBy: { stockQuantity: "asc" }, take: 10, select: { name: true, stockQuantity: true, lowStockAt: true } }),
      prisma.order.findMany({ orderBy: { createdAt: "desc" }, take: 8, select: { orderNumber: true, email: true, totalMinor: true, currency: true, status: true, createdAt: true } }),
      prisma.orderItem.groupBy({ by: ["productId", "productName"], _sum: { quantity: true }, orderBy: { _sum: { quantity: "desc" } }, take: 5 })
    ]);
    response.json({
      metrics: { totalRevenueMinor: revenue._sum.totalMinor ?? 0, totalOrders, totalCustomers, totalProducts, pendingOrders, completedOrders, lowStockProducts: lowStockProducts.length },
      lowStockProducts,
      recentOrders,
      topSellingProducts
    });
  } catch (error) { next(error); }
});

    app.get("/api/admin/analytics", requireAdmin, async (_request, response, next) => {
      try {
        const now = new Date();
        const startOfDay = new Date(now); startOfDay.setHours(0, 0, 0, 0);
        const startOfWeek = new Date(startOfDay); startOfWeek.setDate(startOfWeek.getDate() - 6);
        const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
        const validOrders = { status: { notIn: ["CANCELLED", "REFUNDED"] as ("CANCELLED" | "REFUNDED")[] } };
        const [daily, weekly, monthly, totals, customerOrders, customers, itemRows, viewed] = await Promise.all([
          prisma.order.aggregate({ _sum: { totalMinor: true }, _count: true, where: { ...validOrders, createdAt: { gte: startOfDay } } }),
          prisma.order.aggregate({ _sum: { totalMinor: true }, _count: true, where: { ...validOrders, createdAt: { gte: startOfWeek } } }),
          prisma.order.aggregate({ _sum: { totalMinor: true }, _count: true, where: { ...validOrders, createdAt: { gte: startOfMonth } } }),
          prisma.order.aggregate({ _sum: { totalMinor: true }, _count: true, where: validOrders }),
          prisma.order.findMany({ where: validOrders, select: { userId: true, email: true } }),
          prisma.user.findMany({ where: { role: UserRole.CUSTOMER }, select: { id: true, email: true, createdAt: true } }),
          prisma.orderItem.findMany({ where: { order: validOrders }, include: { product: { select: { category: true } } } }),
          prisma.recentlyViewed.findMany({ orderBy: { viewedAt: "desc" }, take: 500, include: { product: { select: { name: true } } } })
        ]);
        const uniqueCustomers = new Set(customerOrders.map(order => order.userId ?? order.email.toLowerCase()));
        const newCustomers = customers.filter(customer => customer.createdAt >= startOfMonth).length;
        const returningCustomers = customers.filter(customer => customerOrders.filter(order => order.userId === customer.id).length > 1).length;
        const productSales = new Map<string, { name: string; quantity: number }>();
        const categorySales = new Map<string, number>();
        for (const item of itemRows) {
          const current = productSales.get(item.productName) ?? { name: item.productName, quantity: 0 };
          current.quantity += item.quantity; productSales.set(item.productName, current);
          categorySales.set(item.product.category, (categorySales.get(item.product.category) ?? 0) + item.quantity);
        }
        const viewedProducts = new Map<string, { name: string; views: number }>();
        for (const item of viewed) { const current = viewedProducts.get(item.productId) ?? { name: item.product.name, views: 0 }; current.views += 1; viewedProducts.set(item.productId, current); }
        const dailySales = Array.from({ length: 30 }, (_, index) => { const date = new Date(startOfDay); date.setDate(date.getDate() - (29 - index)); return { date: date.toISOString().slice(0, 10), revenueMinor: 0, orders: 0 }; });
        const recentOrders = await prisma.order.findMany({ where: { ...validOrders, createdAt: { gte: dailySales.length ? new Date(`${dailySales[0].date}T00:00:00.000Z`) : startOfMonth } }, select: { createdAt: true, totalMinor: true } });
        for (const order of recentOrders) { const day = dailySales.find(item => item.date === order.createdAt.toISOString().slice(0, 10)); if (day) { day.revenueMinor += order.totalMinor; day.orders += 1; } }
        response.json({
          summary: {
            dailySalesMinor: daily._sum.totalMinor ?? 0, weeklySalesMinor: weekly._sum.totalMinor ?? 0, monthlySalesMinor: monthly._sum.totalMinor ?? 0,
            revenueMinor: totals._sum.totalMinor ?? 0, averageOrderValueMinor: totals._count ? Math.round((totals._sum.totalMinor ?? 0) / totals._count) : 0,
            conversionRate: null, uniqueCustomers: uniqueCustomers.size, newCustomers, returningCustomers, abandonedCarts: null
          },
          dailySales, bestSellingProducts: [...productSales.values()].sort((a, b) => b.quantity - a.quantity).slice(0, 8),
          bestSellingCategories: [...categorySales.entries()].map(([category, quantity]) => ({ category, quantity })).sort((a, b) => b.quantity - a.quantity),
          mostViewedProducts: [...viewedProducts.values()].sort((a, b) => b.views - a.views).slice(0, 8)
        });
      } catch (error) { next(error); }
    });
app.get("/api/admin/products", requireAdmin, async (_request, response, next) => {
  try {
    const products = await prisma.product.findMany({ include: { images: { orderBy: { sortOrder: "asc" } } }, orderBy: { createdAt: "desc" } });
    response.json({ products });
  } catch (error) { next(error); }
});

app.post("/api/admin/uploads", requireAdmin, async (request, response, next) => {
  try {
    const data = z.object({
      filename: z.string().trim().max(160),
      contentType: z.enum(["image/jpeg", "image/png", "image/webp", "image/gif"]),
      data: z.string().regex(/^data:image\/(?:jpeg|png|webp|gif);base64,[A-Za-z0-9+/=\r\n]+$/)
    }).parse(request.body);
    const extension = { "image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "image/gif": "gif" }[data.contentType];
    const buffer = Buffer.from(data.data.split(",")[1], "base64");
    if (buffer.length > 5 * 1024 * 1024) { response.status(413).json({ error: "Each image must be 5 MB or smaller" }); return; }
    const filename = `${crypto.randomUUID()}.${extension}`;
    await fs.mkdir(path.resolve(__dirname, "../../uploads"), { recursive: true });
    await fs.writeFile(path.resolve(__dirname, "../../uploads", filename), buffer, { flag: "wx" });
    response.status(201).json({ url: `/uploads/${filename}` });
  } catch (error) { next(error); }
});

app.post("/api/admin/products", requireAdmin, async (request, response, next) => {
      try {
        const data = productInputSchema.parse(request.body);
        const { images, ...productData } = data;
        const product = await prisma.product.create({
          data: {
            ...productData,
            images: { create: images.map((image, index) => ({ ...image, sortOrder: index })) }
          },
          include: { images: true }
        });
        response.status(201).json({ product });
      } catch (error) { next(error); }
    });

app.patch("/api/admin/products/:id", requireAdmin, async (request, response, next) => {
      try {
        const id = String(request.params.id);
        const data = productInputSchema.parse(request.body);
        const { images, ...productData } = data;
        const product = await prisma.$transaction(async transaction => {
          await transaction.productImage.deleteMany({ where: { productId: id } });
          return transaction.product.update({
            where: { id },
            data: { ...productData, images: { create: images.map((image, index) => ({ ...image, sortOrder: index })) } },
            include: { images: true }
          });
        });
        response.json({ product });
      } catch (error) { next(error); }
    });

app.post("/api/admin/products/:id/duplicate", requireAdmin, async (request, response, next) => {
      try {
        const id = String(request.params.id);
        const source = await prisma.product.findUnique({ where: { id }, include: { images: true } });
        if (!source) { response.status(404).json({ error: "Product not found" }); return; }
        const suffix = `-copy-${Date.now().toString().slice(-6)}`;
        const product = await prisma.product.create({
          data: {
            name: `${source.name} Copy`, slug: `${source.slug}${suffix}`, sku: `${source.sku}${suffix.toUpperCase()}`,
            description: source.description, shortDescription: source.shortDescription, category: source.category, gender: source.gender,
            priceMinor: source.priceMinor, discountMinor: source.discountMinor, costMinor: source.costMinor, stockQuantity: source.stockQuantity,
            lowStockAt: source.lowStockAt, active: false, featured: source.featured, bestSeller: source.bestSeller, newArrival: source.newArrival,
            sizes: source.sizes, colours: source.colours, variants: source.variants ?? undefined, seoTitle: source.seoTitle, seoDescription: source.seoDescription,
            images: { create: source.images.map(image => ({ url: image.url, alt: image.alt, sortOrder: image.sortOrder })) }
          },
          include: { images: true }
        });
        response.status(201).json({ product });
      } catch (error) { next(error); }
    });

app.patch("/api/admin/products/:id/status", requireAdmin, async (request, response, next) => {
      try {
        const id = String(request.params.id);
        const active = z.object({ active: z.boolean() }).parse(request.body).active;
        const product = await prisma.product.update({ where: { id }, data: { active } });
        response.json({ product });
      } catch (error) { next(error); }
    });

app.delete("/api/admin/products/:id", requireAdmin, async (request, response, next) => {
      try {
        const id = String(request.params.id);
        const linkedItems = await prisma.orderItem.count({ where: { productId: id } });
        if (linkedItems) { response.status(409).json({ error: "Products included in orders cannot be deleted; deactivate them instead." }); return; }
        await prisma.product.delete({ where: { id } });
        response.status(204).send();
      } catch (error) { next(error); }
    });

    app.get("/api/admin/orders", requireAdmin, async (request, response, next) => {
      try {
        const search = typeof request.query.search === "string" ? request.query.search.trim() : "";
        const status = typeof request.query.status === "string" ? request.query.status : "";
        const validStatuses = ["PENDING", "PAID", "PROCESSING", "PACKED", "SHIPPED", "OUT_FOR_DELIVERY", "DELIVERED", "CANCELLED", "RETURNED", "REFUNDED"] as const;
        const orders = await prisma.order.findMany({
          where: {
            ...(search ? { OR: [{ orderNumber: { contains: search, mode: "insensitive" } }, { email: { contains: search, mode: "insensitive" } }] } : {}),
            ...(validStatuses.includes(status as typeof validStatuses[number]) ? { status: status as typeof validStatuses[number] } : {})
          },
          include: { items: true, payments: true },
          orderBy: { createdAt: "desc" },
          take: 100
        });
        response.json({ orders });
      } catch (error) { next(error); }
    });

    app.get("/api/admin/orders/:id", requireAdmin, async (request, response, next) => {
      try {
        const order = await prisma.order.findUnique({ where: { id: String(request.params.id) }, include: { items: true, payments: true, user: { select: { name: true, email: true, phone: true } } } });
        if (!order) { response.status(404).json({ error: "Order not found" }); return; }
        response.json({ order });
      } catch (error) { next(error); }
    });

    app.patch("/api/admin/orders/:id/status", requireAdmin, async (request, response, next) => {
      try {
        const data = orderStatusSchema.parse(request.body);
        const order = await prisma.order.update({ where: { id: String(request.params.id) }, data: { status: data.status, trackingNumber: data.trackingNumber ?? null, carrier: data.carrier ?? null }, include: { items: true, payments: true } });
        response.json({ order });
      } catch (error) { next(error); }
    });

    app.post("/api/admin/orders/:id/refund", requireAdmin, async (request, response, next) => {
      try {
        const order = await prisma.order.findUnique({ where: { id: String(request.params.id) }, include: { payments: true } });
        if (!order) { response.status(404).json({ error: "Order not found" }); return; }
        const payment = order.payments.find(item => item.status === "PAID");
        if (!payment) { response.status(400).json({ error: "No paid payment is available to refund" }); return; }
        if (payment.provider === "PAYSTACK") {
          if (!process.env.PAYSTACK_SECRET_KEY || !payment.providerReference) { response.status(503).json({ error: "Paystack refund is not configured for this payment" }); return; }
          const gateway = await fetch("https://api.paystack.co/refund", { method: "POST", headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`, "Content-Type": "application/json" }, body: JSON.stringify({ transaction: payment.providerReference, amount: payment.amountMinor }) });
          if (!gateway.ok) { response.status(502).json({ error: "Paystack refund failed" }); return; }
        } else {
          response.status(501).json({ error: "Flutterwave refunds require provider transaction configuration" }); return;
        }
        await prisma.$transaction([
          prisma.payment.update({ where: { id: payment.id }, data: { status: "REFUNDED" } }),
          prisma.order.update({ where: { id: order.id }, data: { status: "REFUNDED" } })
        ]);
        response.json({ message: "Refund processed" });
      } catch (error) { next(error); }
    });
app.post("/api/auth/register", async (request, response, next) => {
  try {
    const data = authSchema.extend({ name: z.string().trim().min(1).max(100) }).parse(request.body);
    const email = data.email.toLowerCase();
    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) { response.status(409).json({ error: "An account with that email already exists" }); return; }
    const passwordHash = await bcrypt.hash(data.password, 12);
    const user = await prisma.user.create({ data: { email, passwordHash, name: data.name } });
    const token = crypto.randomBytes(32).toString("hex");
    await prisma.emailVerificationToken.create({ data: { id: crypto.randomUUID(), userId: user.id, tokenHash: crypto.createHash("sha256").update(token).digest("hex"), expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) } });
    if (process.env.NODE_ENV !== "production") console.log(`Email verification URL: ${process.env.EMAIL_VERIFICATION_URL}?token=${token}`);
    await createSession(user.id, response);
    response.status(201).json({ user: { id: user.id, email: user.email, name: user.name, role: user.role, emailVerified: false }, message: "Account created. Please verify your email." });
  } catch (error) { next(error); }
});

app.post("/api/auth/verify-email", async (request, response, next) => {
  try {
    const { token } = verificationSchema.parse(request.body);
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    const verification = await prisma.emailVerificationToken.findUnique({ where: { tokenHash } });
    if (!verification || verification.usedAt || verification.expiresAt <= new Date()) { response.status(400).json({ error: "Verification link is invalid or expired" }); return; }
    await prisma.$transaction([
      prisma.user.update({ where: { id: verification.userId }, data: { emailVerifiedAt: new Date() } }),
      prisma.emailVerificationToken.update({ where: { id: verification.id }, data: { usedAt: new Date() } })
    ]);
    response.json({ message: "Email verified successfully" });
  } catch (error) { next(error); }
});

app.post("/api/auth/login", async (request, response, next) => {
  try {
    const data = authSchema.parse(request.body);
    const user = await prisma.user.findUnique({ where: { email: data.email.toLowerCase() } });
    if (!user || !(await bcrypt.compare(data.password, user.passwordHash))) { response.status(401).json({ error: "Invalid email or password" }); return; }
    await createSession(user.id, response);
    response.json({ user: { id: user.id, email: user.email, name: user.name, role: user.role, emailVerified: Boolean(user.emailVerifiedAt) } });
  } catch (error) { next(error); }
});

app.post("/api/auth/forgot-password", async (request, response, next) => {
  try {
    const email = z.object({ email: z.string().trim().email().max(254) }).parse(request.body).email.toLowerCase();
    const user = await prisma.user.findUnique({ where: { email } });
    if (user) {
      const token = crypto.randomBytes(32).toString("hex");
      const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
      await prisma.passwordResetToken.deleteMany({ where: { userId: user.id, usedAt: null } });
      await prisma.passwordResetToken.create({ data: { id: crypto.randomUUID(), userId: user.id, tokenHash, expiresAt: new Date(Date.now() + 60 * 60 * 1000) } });
      if (process.env.NODE_ENV !== "production") console.log(`Password reset URL: ${process.env.PASSWORD_RESET_URL}?token=${token}`);
    }
    response.json({ message: "If an account exists for that email, a reset link has been sent." });
  } catch (error) { next(error); }
});

app.post("/api/auth/reset-password", async (request, response, next) => {
  try {
    const data = resetSchema.parse(request.body);
    const tokenHash = crypto.createHash("sha256").update(data.token).digest("hex");
    const resetToken = await prisma.passwordResetToken.findUnique({ where: { tokenHash } });
    if (!resetToken || resetToken.usedAt || resetToken.expiresAt <= new Date()) { response.status(400).json({ error: "Reset link is invalid or expired" }); return; }
    await prisma.$transaction([
      prisma.user.update({ where: { id: resetToken.userId }, data: { passwordHash: await bcrypt.hash(data.password, 12) } }),
      prisma.passwordResetToken.update({ where: { id: resetToken.id }, data: { usedAt: new Date() } }),
      prisma.session.deleteMany({ where: { userId: resetToken.userId } })
    ]);
    response.json({ message: "Password reset successfully" });
  } catch (error) { next(error); }
});

app.post("/api/auth/logout", requireAuth, async (request, response, next) => {
  try { const sessionId = cookieValue(request); if (sessionId) await prisma.session.deleteMany({ where: { id: sessionId } }); clearSessionCookie(response); response.status(204).end(); } catch (error) { next(error); }
});

app.get("/api/auth/me", requireAuth, async (request: AuthRequest, response, next) => {
  try { const user = await prisma.user.findUnique({ where: { id: request.user!.id }, select: { id: true, email: true, name: true, phone: true, role: true, emailVerifiedAt: true } }); response.json({ user: user ? { ...user, emailVerified: Boolean(user.emailVerifiedAt) } : null }); } catch (error) { next(error); }
});

app.patch("/api/account/profile", requireAuth, async (request: AuthRequest, response, next) => {
  try { const data = profileSchema.parse(request.body); const user = await prisma.user.update({ where: { id: request.user!.id }, data }); response.json({ user: { id: user.id, email: user.email, name: user.name, phone: user.phone } }); } catch (error) { next(error); }
});

app.patch("/api/account/password", requireAuth, async (request: AuthRequest, response, next) => {
  try {
    const data = passwordSchema.parse(request.body);
    const user = await prisma.user.findUnique({ where: { id: request.user!.id } });
    if (!user || !(await bcrypt.compare(data.currentPassword, user.passwordHash))) { response.status(400).json({ error: "Current password is incorrect" }); return; }
    await prisma.user.update({ where: { id: user.id }, data: { passwordHash: await bcrypt.hash(data.newPassword, 12) } });
    response.json({ message: "Password updated successfully" });
  } catch (error) { next(error); }
});

app.get("/api/account/orders", requireAuth, async (request: AuthRequest, response, next) => {
  try { const orders = await prisma.order.findMany({ where: { userId: request.user!.id }, include: { items: true }, orderBy: { createdAt: "desc" } }); response.json({ orders }); } catch (error) { next(error); }
});

app.get("/api/account/addresses", requireAuth, async (request: AuthRequest, response, next) => {
  try { response.json({ addresses: await prisma.address.findMany({ where: { userId: request.user!.id }, orderBy: [{ isDefault: "desc" }, { createdAt: "asc" }] }) }); } catch (error) { next(error); }
});

app.post("/api/account/addresses", requireAuth, async (request: AuthRequest, response, next) => {
  try {
    const data = z.object({ label: z.string().trim().min(1).max(40), street: z.string().trim().min(1).max(200), city: z.string().trim().min(1).max(80), state: z.string().trim().min(1).max(80) }).parse(request.body);
    const count = await prisma.address.count({ where: { userId: request.user!.id } });
    const address = await prisma.address.create({ data: { userId: request.user!.id, ...data, firstName: "", lastName: "", country: "Nigeria", isDefault: count === 0 } });
    response.status(201).json({ address });
  } catch (error) { next(error); }
});

app.patch("/api/account/addresses/:id/default", requireAuth, async (request: AuthRequest, response, next) => {
  try {
    const id = String(request.params.id);
    const address = await prisma.address.findFirst({ where: { id, userId: request.user!.id } });
    if (!address) { response.status(404).json({ error: "Address not found" }); return; }
    await prisma.$transaction([
      prisma.address.updateMany({ where: { userId: request.user!.id }, data: { isDefault: false } }),
      prisma.address.update({ where: { id }, data: { isDefault: true } })
    ]);
    response.json({ message: "Default address updated" });
  } catch (error) { next(error); }
});

app.post("/api/payments/initialize", async (request, response, next) => {
  try {
    const data = paymentSchema.parse(request.body);
    const products = await prisma.product.findMany({ where: { sku: { in: data.items.map(item => item.sku) }, active: true } });
    const productMap = new Map(products.map(product => [product.sku, product]));
    const orderItems = data.items.map(item => {
      const product = productMap.get(item.sku);
      if (!product) throw new Error("One or more products are unavailable");
      if (product.stockQuantity < item.quantity) throw new Error(`${product.name} does not have enough stock`);
      return { productId: product.id, productName: product.name, unitPriceMinor: product.discountMinor ?? product.priceMinor, quantity: item.quantity };
    });
    const subtotalMinor = orderItems.reduce((total, item) => total + item.unitPriceMinor * item.quantity, 0);
    const orderNumber = `MV-${Date.now().toString().slice(-8)}`;
    const sessionId = cookieValue(request);
    const session = sessionId ? await prisma.session.findUnique({ where: { id: sessionId } }) : null;
    const userId = session && session.expiresAt > new Date() ? session.userId : undefined;
    const order = await prisma.order.create({
      data: {
        orderNumber, userId, email: data.email, currency: data.currency,
        subtotalMinor, shippingMinor: 0, totalMinor: subtotalMinor,
        items: { create: orderItems }
      }
    });
    const reference = `${orderNumber}-${crypto.randomBytes(6).toString("hex")}`;
    await prisma.payment.create({ data: { orderId: order.id, provider: data.provider === "paystack" ? "PAYSTACK" : "FLUTTERWAVE", reference, amountMinor: subtotalMinor, currency: data.currency } });
    if (data.provider === "paystack") {
      if (!process.env.PAYSTACK_SECRET_KEY) { response.status(503).json({ error: "Paystack is not configured" }); return; }
      const gateway = await fetch("https://api.paystack.co/transaction/initialize", {
        method: "POST", headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`, "Content-Type": "application/json" },
        body: JSON.stringify({ email: data.email, amount: subtotalMinor, currency: data.currency, reference, callback_url: process.env.PAYMENT_CALLBACK_URL })
      });
      const result = await gateway.json() as { status?: boolean; message?: string; data?: { authorization_url: string; access_code: string; reference: string } };
      if (!gateway.ok || !result.status || !result.data) { response.status(502).json({ error: result.message ?? "Paystack initialization failed" }); return; }
      response.status(201).json({ provider: "paystack", orderId: order.id, reference, authorizationUrl: result.data.authorization_url });
      return;
    }
    if (!process.env.FLUTTERWAVE_SECRET_KEY) { response.status(503).json({ error: "Flutterwave is not configured" }); return; }
    const gateway = await fetch("https://api.flutterwave.com/v3/payments", {
      method: "POST", headers: { Authorization: `Bearer ${process.env.FLUTTERWAVE_SECRET_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ tx_ref: reference, amount: (subtotalMinor / 100).toFixed(2), currency: data.currency, redirect_url: process.env.PAYMENT_CALLBACK_URL, customer: { email: data.email }, customizations: { title: "MAYOR VOGUE" } })
    });
    const result = await gateway.json() as { status?: string; message?: string; data?: { link: string } };
    if (!gateway.ok || result.status !== "success" || !result.data) { response.status(502).json({ error: result.message ?? "Flutterwave initialization failed" }); return; }
    response.status(201).json({ provider: "flutterwave", orderId: order.id, reference, authorizationUrl: result.data.link });
  } catch (error) { next(error); }
});

app.get("/api/payments/verify/:provider/:reference", async (request, response, next) => {
  try {
    const provider = z.enum(["paystack", "flutterwave"]).parse(request.params.provider);
    const reference = z.string().min(1).parse(request.params.reference);
    const payment = await prisma.payment.findUnique({ where: { reference }, include: { order: true } });
    if (!payment) { response.status(404).json({ error: "Payment not found" }); return; }
    let paid = false;
    let providerReference: string | undefined;
    if (provider === "paystack") {
      if (!process.env.PAYSTACK_SECRET_KEY) { response.status(503).json({ error: "Paystack is not configured" }); return; }
      const gateway = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`, { headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` } });
      const result = await gateway.json() as { data?: { status: string; reference: string } };
      paid = gateway.ok && result.data?.status === "success";
      providerReference = result.data?.reference;
    } else {
      if (!process.env.FLUTTERWAVE_SECRET_KEY) { response.status(503).json({ error: "Flutterwave is not configured" }); return; }
      const gateway = await fetch(`https://api.flutterwave.com/v3/transactions/verify_by_reference?tx_ref=${encodeURIComponent(reference)}`, { headers: { Authorization: `Bearer ${process.env.FLUTTERWAVE_SECRET_KEY}` } });
      const result = await gateway.json() as { data?: { status: string; tx_ref: string } };
      paid = gateway.ok && result.data?.status === "successful";
      providerReference = result.data?.tx_ref;
    }
    if (paid) {
      await prisma.$transaction([
        prisma.payment.update({ where: { id: payment.id }, data: { status: "PAID", providerReference } }),
        prisma.order.update({ where: { id: payment.orderId }, data: { status: "PAID" } })
      ]);
    }
    response.json({ reference, status: paid ? "PAID" : "PENDING" });
  } catch (error) { next(error); }
});

app.use((error: unknown, _request: Request, response: Response, _next: NextFunction) => {
  if (error instanceof z.ZodError) { response.status(400).json({ error: "Invalid request", details: error.flatten().fieldErrors }); return; }
  console.error(error);
  response.status(500).json({ error: "Internal server error" });
});

app.listen(port, () => console.log(`MAYOR VOGUE API listening on http://localhost:${port}`));
