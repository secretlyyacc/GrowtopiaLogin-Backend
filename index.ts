import express, { Request, Response } from 'express';
import cors from 'cors';
import path from 'path';
import fs from 'fs';

const app = express();

// @note middleware basic
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// @note health check
app.get('/', (_req: Request, res: Response) => {
    res.json({ status: 'ok', message: 'Server is running' });
});

/**
 * @note login validate endpoint
 */
app.post('/player/growid/login/validate', async (req: Request, res: Response) => {
    try {
        const { growId, password, _token } = req.body;
        
        if (!growId || !password) {
            return res.status(400).json({
                status: 'error',
                message: 'Missing growId or password'
            });
        }

        const token = Buffer.from(
            `_token=${_token || ''}&growId=${growId}&password=${password}&reg=0`
        ).toString('base64');

        res.json({
            status: 'success',
            message: 'Account Validated.',
            token: token,
            url: '',
            accountType: 'growtopia'
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            status: 'error',
            message: 'Internal Server Error'
        });
    }
});

/**
 * @note checktoken endpoint
 */
app.post('/player/growid/checktoken', async (req: Request, res: Response) => {
    try {
        const body = req.body;
        let refreshToken: string | undefined;
        let clientData: string | undefined;

        // Parse berbagai format
        if (body.data) {
            refreshToken = body.data.refreshToken;
            clientData = body.data.clientData;
        } else {
            refreshToken = body.refreshToken;
            clientData = body.clientData;
        }

        if (!refreshToken || !clientData) {
            return res.status(400).json({
                status: 'error',
                message: 'Missing refreshToken or clientData'
            });
        }

        // Decode token
        const decodeRefreshToken = Buffer.from(refreshToken, 'base64').toString('utf-8');
        
        // Update token
        const newToken = Buffer.from(
            decodeRefreshToken.replace(
                /(_token=)[^&]*/,
                `$1${Buffer.from(clientData).toString('base64')}`
            )
        ).toString('base64');

        res.json({
            status: 'success',
            message: 'Token is valid.',
            token: newToken,
            url: '',
            accountType: 'growtopia'
        });
    } catch (error) {
        console.error('Checktoken error:', error);
        res.status(500).json({
            status: 'error',
            message: 'Internal Server Error'
        });
    }
});

/**
 * @note dashboard endpoint
 */
app.all('/player/login/dashboard', async (req: Request, res: Response) => {
    try {
        const tData: Record<string, string> = {};

        // Parse body
        if (req.body && typeof req.body === 'object') {
            try {
                const bodyStr = JSON.stringify(req.body);
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
            } catch (e) {
                console.log('Parse error:', e);
            }
        }

        // Convert to base64
        const tDataBase64 = Buffer.from(JSON.stringify(tData)).toString('base64');

        // Read template
        const templatePath = path.join(process.cwd(), 'template', 'dashboard.html');
        
        if (!fs.existsSync(templatePath)) {
            return res.status(404).send('Template not found');
        }

        let templateContent = fs.readFileSync(templatePath, 'utf-8');
        templateContent = templateContent.replace('{{ data }}', tDataBase64);

        res.setHeader('Content-Type', 'text/html');
        res.send(templateContent);
    } catch (error) {
        console.error('Dashboard error:', error);
        res.status(500).send('Internal Server Error');
    }
});

// @note untuk backward compatibility
app.all('/player/growid/validate/checktoken', async (req: Request, res: Response) => {
    // Forward ke endpoint utama
    const response = await fetch('https://gtlyy-backend.vercel.app/player/growid/checktoken', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(req.body)
    });
    
    const data = await response.json();
    res.json(data);
});

// @note 404 handler
app.use((_req: Request, res: Response) => {
    res.status(404).json({
        status: 'error',
        message: 'Endpoint not found'
    });
});

// @note export untuk Vercel
export default app;
