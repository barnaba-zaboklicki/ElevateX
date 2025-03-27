# Innovation Hub Platform - Technical Documentation

## Table of Contents

### 1. Project Overview
- [Introduction](./overview/introduction.md)
- [Architecture](./overview/architecture.md)
- [Getting Started](./overview/getting-started.md)

### 2. Components
- [Authentication Components](./components/auth/README.md)
  - [LoginForm](./components/auth/LoginForm.md)
  - [RegisterForm](./components/auth/RegisterForm.md)
  - [ProtectedRoute](./components/auth/ProtectedRoute.md)

### 3. Context
- [Authentication Context](./context/AuthContext.md)

### 4. Services
- [Authentication Service](./services/authService.md)

### 5. Styling
- [CSS Documentation](./styles/README.md)
  - [Auth Styles](./styles/auth/README.md)
  - [Common Styles](./styles/common/README.md)

### 6. Configuration
- [Package Configuration](./config/package.md)
- [TypeScript Configuration](./config/tsconfig.md)

## Quick Start

1. Install dependencies:
```bash
npm install
```

2. Start development server:
```bash
npm start
```

3. Build for production:
```bash
npm run build
```

## Project Structure

```
frontend/
├── src/
│   ├── components/
│   │   └── auth/
│   │       ├── LoginForm.tsx
│   │       ├── RegisterForm.tsx
│   │       └── ProtectedRoute.tsx
│   ├── context/
│   │   └── AuthContext.tsx
│   ├── services/
│   │   └── authService.ts
│   ├── styles/
│   │   ├── auth/
│   │   │   ├── LoginForm.css
│   │   │   └── RegisterForm.css
│   │   └── common/
│   │       ├── App.css
│   │       └── LoadingSpinner.css
│   └── App.tsx
├── docs/
│   ├── overview/
│   ├── components/
│   ├── context/
│   ├── services/
│   ├── styles/
│   └── config/
├── package.json
└── tsconfig.json
```

## Contributing

Please read our [Contributing Guidelines](./CONTRIBUTING.md) before submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details. 