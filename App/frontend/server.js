const https = require('https');
const fs = require('fs');
const path = require('path');

// SSL configuration
const SSL_CERT_PATH = '../backend/cert.pem';
const SSL_KEY_PATH = '../backend/key.pem';

const options = {
    key: fs.readFileSync(SSL_KEY_PATH),
    cert: fs.readFileSync(SSL_CERT_PATH)
};

// Base directory for serving files
const BASE_DIR = path.join(__dirname);

function tryPaths(urlPath) {
    const paths = [
        path.join(BASE_DIR, urlPath),
        path.join(BASE_DIR, 'src', urlPath),
        path.join(BASE_DIR, 'public', urlPath),
        // Handle relative paths from src/pages/landing/
        path.join(BASE_DIR, 'src/pages/landing', urlPath),
        // Handle dashboard paths
        path.join(BASE_DIR, 'src/pages/dashboard', urlPath),
        // Try to resolve relative paths (../../)
        path.resolve(BASE_DIR, urlPath)
    ];

    console.log('Trying paths:');
    for (const p of paths) {
        console.log(`- ${p} (${fs.existsSync(p) ? 'exists' : 'not found'})`);
        if (fs.existsSync(p) && !fs.statSync(p).isDirectory()) {
            return p;
        }
    }
    return null;
}

const server = https.createServer(options, (req, res) => {
    console.log(`\nIncoming request: ${req.url}`);
    
    // Normalize the URL to prevent directory traversal
    let urlPath = path.normalize(req.url).replace(/^(\.\.[\/\\])+/, '');
    urlPath = urlPath.split('?')[0]; // Remove query strings
    
    console.log(`Normalized path: ${urlPath}`);

    // Default to index.html for root path
    if (urlPath === '/' || urlPath === '' || urlPath === '\\') {
        urlPath = 'src/pages/landing/index.html';
        console.log(`Using default path: ${urlPath}`);
    } else {
        // Remove leading slash
        urlPath = urlPath.replace(/^[\/\\]/, '');
    }

    // Try to find the file
    let filePath = tryPaths(urlPath);
    
    if (!filePath && urlPath.includes('../')) {
        // Try without the leading slash for relative paths
        filePath = tryPaths(urlPath);
    }

    if (!filePath) {
        console.log('File not found in any location');
        res.writeHead(404);
        res.end(`File not found: ${urlPath}`);
        return;
    }

    // Serve the file
    const contentType = getContentType(filePath);
    console.log(`Serving ${filePath} as ${contentType}`);
    
    fs.readFile(filePath, (error, content) => {
        if (error) {
            console.error(`Error reading file: ${error}`);
            res.writeHead(500);
            res.end(`Server error: ${error.code}`);
            return;
        }

        res.writeHead(200, {
            'Content-Type': contentType,
            'Cache-Control': 'no-cache'
        });
        res.end(content);
    });
});

function getContentType(filePath) {
    const extname = path.extname(filePath).toLowerCase();
    const contentTypes = {
        '.html': 'text/html',
        '.js': 'text/javascript',
        '.css': 'text/css',
        '.json': 'application/json',
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.gif': 'image/gif',
        '.ico': 'image/x-icon',
        '.svg': 'image/svg+xml',
        '.JPG': 'image/jpeg'
    };
    return contentTypes[extname] || 'application/octet-stream';
}

const PORT = 3000;
server.listen(PORT, () => {
    console.log(`Frontend server running at https://localhost:${PORT}/`);
    console.log(`Base directory: ${BASE_DIR}`);
}); 