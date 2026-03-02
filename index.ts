import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import path from 'path';
import fs from 'fs';

const app = express();
const PORT = 3000;

// @note trust proxy - set to number of proxies in front of app
app.set('trust proxy', 1);

// @note middleware setup - URUTAN PENTING!
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    credentials: true
}));

// @note GANTI INI: Hapus app.options('*', cors()) dan ganti dengan route spesifik
// Biar cors() handle OPTIONS secara otomatis

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// @note rate limiter - 50 requests per minute
const limiter = rateLimit({
  windowMs: 60_000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false, xForwardedForHeader: false },
  keyGenerator: (req) => {
    return req.headers['x-forwarded-for']?.toString() || req.socket.remoteAddress || 'unknown';
  },
  // @note skip failed requests biar ga crash
  skip: (req) => req.method === 'OPTIONS'
});
app.use(limiter);

// @note static files from public folder
app.use(express.static(path.join(process.cwd(), 'public')));

// @note request logging middleware
app.use((req: Request, res: Response, next: NextFunction) => {
  const clientIp =
    (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
    req.headers['x-real-ip'] ||
    req.socket.remoteAddress ||
    'unknown';

  console.log(
    `[REQ] ${req.method} ${req.path} → ${clientIp} | ${req.headers['user-agent']}`,
  );
  
  // @note log body for debugging (optional)
  if (req.method === 'POST' && req.path.includes('login')) {
    console.log(`[BODY]`, req.body);
  }
  
  next();
});

// @note root endpoint
app.get('/', (_req: Request, res: Response) => {
  res.send('Hello, world!');
});

/**
 * @note dashboard endpoint - serves login HTML page with client data
 * @param req - express request with optional body data
 * @param res - express response
 */
app.all('/player/login/dashboard', async (req: Request, res: Response) => {
  try {
    const tData: Record<string, string> = {};

    // @note handle empty body or missing data
    const body = req.body;
    if (body && typeof body === 'object' && Object.keys(body).length > 0) {
      try {
        const bodyStr = JSON.stringify(body);
        const parts = bodyStr.split('"');

        if (parts.length > 1) {
          const uData = parts[1].split('\n');
          for (let i = 0; i < uData.length - 1; i++) {
            const d = uData[i].split('|');
            if (d.length === 2) {
              tData[d[0]] = d[1];
            }
          }
        }
      } catch (why) {
        console.log(`[ERROR]: ${why}`);
      }
    }

    // @note convert tData object to base64 string
    const tDataBase64 = Buffer.from(JSON.stringify(tData)).toString('base64');

    // @note read dashboard template and replace placeholder
    const templatePath = path.join(
      process.cwd(),
      'template',
      'dashboard.html',
    );

    // @note check if template exists
    if (!fs.existsSync(templatePath)) {
      return res.status(404).send('Template not found');
    }

    const templateContent = fs.readFileSync(templatePath, 'utf-8');
    const htmlContent = templateContent.replace('{{ data }}', tDataBase64);

    res.setHeader('Content-Type', 'text/html');
    res.send(htmlContent);
  } catch (error) {
    console.log(`[ERROR]: ${error}`);
    res.status(500).send('Internal Server Error');
  }
});

/**
 * @note validate login endpoint - validates GrowID credentials
 * @param req - express request with growId, password, _token
 * @param res - express response with token
 */
app.all(
  '/player/growid/login/validate',
  async (req: Request, res: Response) => {
    try {
      console.log('[VALIDATE] Request received:', req.method);
      console.log('[VALIDATE] Headers:', req.headers);
      console.log('[VALIDATE] Body:', req.body);
      
      const formData = req.body as Record<string, string>;
      const _token = formData._token;
      const growId = formData.growId;
      const password = formData.password;

      // @note validate required fields
      if (!growId || !password) {
        return res.status(400).json({
          status: 'error',
          message: 'Missing growId or password',
        });
      }

      const token = Buffer.from(
        `_token=${_token || ''}&growId=${growId}&password=${password}&reg=0`,
      ).toString('base64');

      res.setHeader('Content-Type', 'application/json');
      res.json({
        status: 'success',
        message: 'Account Validated.',
        token: token,
        url: '',
        accountType: 'growtopia',
      });
    } catch (error) {
      console.log(`[ERROR]: ${error}`);
      res.status(500).json({
        status: 'error',
        message: 'Internal Server Error',
      });
    }
  },
);

/**
 * @note first checktoken endpoint - gak pake redirect lagi biar aman di Vercel
 * @param req - express request with refreshToken and clientData
 * @param res - express response with updated token
 */
app.all('/player/growid/checktoken', async (req: Request, res: Response) => {
  console.log('[CHECKTOKEN1] Request received:', req.method);
  console.log('[CHECKTOKEN1] Body:', req.body);
  console.log('[CHECKTOKEN1] Query:', req.query);
  
  // @note langsung forward ke logic yang sama
  try {
    // @note handle both { data: { ... } } and { refreshToken, clientData } formats
    const body = req.body as
      | { data: { refreshToken: string; clientData: string } }
      | { refreshToken: string; clientData: string };

    let refreshToken: string | undefined;
    let clientData: string | undefined;

    if ('data' in body && body.data) {
      refreshToken = body.data?.refreshToken;
      clientData = body.data?.clientData;
    } else {
      refreshToken = (body as any).refreshToken;
      clientData = (body as any).clientData;
    }

    // @note juga cek query params untuk GET requests
    if (!refreshToken && req.query.refreshToken) {
      refreshToken = req.query.refreshToken as string;
    }
    if (!clientData && req.query.clientData) {
      clientData = req.query.clientData as string;
    }

    if (!refreshToken || !clientData) {
      return res.status(400).json({
        status: 'error',
        message: 'Missing refreshToken or clientData',
      });
    }

    let decodeRefreshToken = Buffer.from(refreshToken, 'base64').toString(
      'utf-8',
    );

    const newToken = Buffer.from(
      decodeRefreshToken.replace(
        /(_token=)[^&]*/,
        `$1${Buffer.from(clientData).toString('base64')}`,
      ),
    ).toString('base64');

    res.json({
      status: 'success',
      message: 'Token is valid.',
      token: newToken,
      url: '',
      accountType: 'growtopia'
    });
  } catch (error) {
    console.log(`[ERROR]: ${error}`);
    res.status(500).json({
      status: 'error',
      message: 'Internal Server Error',
    });
  }
});

/**
 * @note second checktoken endpoint - biarin aja, tapi bakal jarang dipake
 */
app.all(
  '/player/growid/validate/checktoken',
  async (req: Request, res: Response) => {
    // @note redirect ke endpoint utama
    res.redirect(307, '/player/growid/checktoken');
  },
);

// @note 404 handler
app.use((_req: Request, res: Response) => {
  res.status(404).json({
    status: 'error',
    message: 'Endpoint not found'
  });
});

// @note error handler
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  console.error('[ERROR]', err);
  res.status(500).json({
    status: 'error',
    message: 'Internal Server Error'
  });
});

// @note untuk Vercel, export app instead of listening
export default app;

// @note kalo jalan lokal, pake ini
if (require.main === module) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[SERVER] Running on http://0.0.0.0:${PORT}`);
    console.log(`[SERVER] Local: http://localhost:${PORT}`);
  });
}
