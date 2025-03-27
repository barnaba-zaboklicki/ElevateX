# Getting Started with Innovation Hub Platform

## Prerequisites

- Node.js 16 or higher
- npm 7 or higher
- Git

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/innovation-hub-platform.git
cd innovation-hub-platform/App/frontend
```

2. Install dependencies:
```bash
npm install
```

3. Create environment file:
```bash
cp .env.example .env
```

4. Configure environment variables:
```env
REACT_APP_API_URL=http://localhost:5000/api
```

## Development

1. Start the development server:
```bash
npm start
```

2. Open your browser and navigate to:
```
http://localhost:3000
```

3. The application will automatically reload when you make changes.

## Building for Production

1. Create a production build:
```bash
npm run build
```

2. The build output will be in the `build` directory.

3. Test the production build locally:
```bash
npx serve -s build
```

## Project Structure

```
frontend/
├── src/
│   ├── components/     # React components
│   ├── context/       # React context providers
│   ├── services/      # API services
│   ├── styles/        # CSS styles
│   └── App.tsx        # Main application component
├── public/            # Static files
├── docs/             # Documentation
└── package.json      # Project configuration
```

## Available Scripts

- `npm start`: Runs the app in development mode
- `npm test`: Launches the test runner
- `npm run build`: Builds the app for production
- `npm run eject`: Ejects from Create React App

## Development Guidelines

### Code Style

- Use TypeScript for all new files
- Follow ESLint rules
- Use Prettier for code formatting
- Write meaningful commit messages

### Component Structure

```typescript
// ComponentName.tsx
import React from 'react';
import './ComponentName.css';

interface Props {
  // Props interface
}

const ComponentName: React.FC<Props> = ({ prop1, prop2 }) => {
  // Component logic

  return (
    // JSX
  );
};

export default ComponentName;
```

### CSS Guidelines

- Use CSS modules for component-specific styles
- Follow BEM naming convention
- Keep styles modular and reusable
- Use variables for colors and measurements

## Testing

1. Run tests:
```bash
npm test
```

2. Run tests with coverage:
```bash
npm test -- --coverage
```

## Debugging

1. Install React Developer Tools browser extension
2. Use Chrome DevTools for debugging
3. Check the console for errors
4. Use React DevTools for component inspection

## Common Issues

### Build Errors

1. Clear node_modules and reinstall:
```bash
rm -rf node_modules
npm install
```

2. Clear npm cache:
```bash
npm cache clean --force
```

### TypeScript Errors

1. Check type definitions:
```bash
npm install --save-dev @types/react @types/react-dom
```

2. Update TypeScript configuration if needed

## Deployment

1. Build the application:
```bash
npm run build
```

2. Deploy the `build` directory to your hosting service

### Deployment Options

- Vercel
- Netlify
- AWS S3 + CloudFront
- Heroku

## Contributing

1. Create a new branch:
```bash
git checkout -b feature/your-feature-name
```

2. Make your changes

3. Commit your changes:
```bash
git commit -m "Add your feature"
```

4. Push to the branch:
```bash
git push origin feature/your-feature-name
```

5. Create a Pull Request

## Support

For support, please:
1. Check the documentation
2. Search existing issues
3. Create a new issue if needed

## License

This project is licensed under the MIT License - see the LICENSE file for details. 