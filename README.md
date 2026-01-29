# iGSIM AI Agent Platform

**iGSIM AI Agent powered by eSIM Myanmar**

A comprehensive AI Agent platform featuring eSIM AI Agent M2M and Smart Website services built with modern technologies and deployed on Firebase. This platform combines Python backend services with Next.js frontend, following 2026 AI Agent standards with systematic approach to UI/UX design.

## 🚀 Features

### Core Services
- **eSIM AI Agent M2M**: Advanced eSIM provisioning and M2M device management
- **Smart Website Services**: Modern responsive web interface with AI integration
- **Multi-AI Integration**: Google Gemini, xai, and groq APIs
- **Real-time Analytics**: Comprehensive monitoring and reporting
- **PyQt/PySide GUI**: Desktop application for system management

### AI Capabilities
- **Google Gemini API**: Advanced language processing and technical tasks
- **xai Integration**: Creative and conversational AI capabilities
- **groq Processing**: High-speed analysis and processing
- **MCP Protocol Support**: Model Context Protocol integration
- **Intelligent Routing**: Automatic AI provider selection based on task type

### eSIM & M2M Features
- **Automated eSIM Provisioning**: Generate and manage eSIM profiles
- **M2M Device Management**: Register, activate, and monitor IoT devices
- **Real-time Device Status**: Live monitoring of device connections
- **Multi-protocol Support**: MQTT, CoAP, HTTP/HTTPS protocols
- **Firebase Integration**: Cloud-based data storage and synchronization

## 🛠 Technology Stack

### Backend
- **Python 3.11+** with async/await support
- **FastAPI** for RESTful API services
- **PyQt6/PySide6** for desktop GUI application
- **Firebase Admin SDK** for cloud integration
- **Google Cloud APIs** for AI services

### Frontend
- **Next.js 14** with App Router
- **React 18** with TypeScript
- **Tailwind CSS** for styling
- **Heroicons** for UI icons
- **Responsive Design** inspired by accio.com

### Cloud & Deployment
- **Firebase Hosting** for web deployment
- **Google Cloud Platform** for backend services
- **Firestore** for database storage
- **Firebase Functions** for serverless computing
- **Automated CI/CD** with git push deployment

## 📋 Prerequisites

### Required Software
- **Node.js 18+** and npm 9+
- **Python 3.11+**
- **Firebase CLI**: `npm install -g firebase-tools`
- **Google Cloud CLI** (already configured)

### API Keys Required
- Google Gemini API key
- xai API key (optional)
- groq API key (optional)

## 🚀 Quick Start

### 1. Clone and Setup
```bash
git clone https://github.com/nexorasim/igsims.git
cd igsims

# Install all dependencies
npm run setup
```

### 2. Environment Configuration
```bash
# Copy environment template
cp .env.example .env

# Edit .env with your API keys
# GEMINI_API_KEY=your_gemini_api_key_here
# XAI_API_KEY=your_xai_api_key_here
# GROQ_API_KEY=your_groq_api_key_here
```

### 3. Development Modes

#### Web Development
```bash
# Start Next.js development server
npm run dev

# Start Python FastAPI server
npm run python:web
```

#### Desktop GUI Application
```bash
# Launch PyQt/PySide GUI
npm run python:gui
```

#### Console Mode (Testing)
```bash
# Run in console mode for testing
npm run python:console
```

## 🌐 Deployment

### Automated Deployment
```bash
# Deploy to Firebase Hosting
npm run deploy

# Or use the Python deployment script
python deploy.py
```

### Manual Deployment Steps
```bash
# 1. Build frontend
npm run build

# 2. Deploy to Firebase
firebase deploy --only hosting

# 3. Deploy with functions (if needed)
firebase deploy
```

### Live URLs
- **Production**: https://bamboo-reason-483913-i4.web.app
- **Firebase Console**: https://console.firebase.google.com/project/bamboo-reason-483913-i4

## 📖 API Documentation

### AI Agent Endpoints
```bash
POST /ai/request          # Process AI request
GET  /ai/status           # Get AI service status
GET  /health              # Health check all services
```

### eSIM Management Endpoints
```bash
POST /esim/provision      # Provision new eSIM profile
GET  /esim/devices        # List active eSIM devices
GET  /esim/device/{id}    # Get specific device status
```

### M2M Device Endpoints
```bash
POST /m2m/manage          # Manage M2M device operations
POST /m2m/register        # Register new M2M device
GET  /m2m/devices         # List all M2M devices
```

### Analytics Endpoints
```bash
GET  /analytics           # Get platform analytics
```

## 🖥 GUI Application

The PyQt/PySide GUI provides a comprehensive desktop interface:

### Main Features
- **AI Agent Tab**: Send requests to different AI providers
- **eSIM Management**: Provision and manage eSIM profiles
- **M2M Devices**: Register and control IoT devices
- **Analytics Dashboard**: Real-time statistics and monitoring
- **Settings Panel**: Configuration and service status

### Launch GUI
```bash
cd src
python main.py --gui
```

## 🔧 Development

### Project Structure
```
igsims/
├── app/                    # Next.js frontend
│   ├── page.tsx           # Main landing page
│   ├── layout.tsx         # Root layout
│   └── globals.css        # Global styles
├── src/                   # Python backend
│   ├── main.py           # Main entry point
│   ├── api/              # FastAPI web API
│   ├── gui/              # PyQt/PySide GUI
│   ├── services/         # Core business logic
│   ├── config/           # Configuration management
│   └── utils/            # Utility functions
├── firebase.json         # Firebase configuration
├── package.json          # Node.js dependencies
├── requirements.txt      # Python dependencies
└── deploy.py            # Deployment automation
```

### Code Quality
```bash
# Python linting and formatting
pip install ruff black mypy
ruff check src/
black src/
mypy src/

# JavaScript/TypeScript linting
npm run lint
```

### Testing
```bash
# Python tests
pytest src/tests/

# Run with coverage
pytest --cov=src src/tests/
```

## 🔐 Security & Configuration

### Firebase Security Rules
- Authenticated access for eSIM and M2M data
- Read-only analytics for authenticated users
- Admin-only write access for sensitive operations

### Environment Variables
```bash
# Required
GEMINI_API_KEY=your_gemini_api_key
FIREBASE_PROJECT_ID=bamboo-reason-483913-i4

# Optional
XAI_API_KEY=your_xai_api_key
GROQ_API_KEY=your_groq_api_key
DEBUG=true
LOG_LEVEL=INFO
```

## 📊 Monitoring & Analytics

### Built-in Analytics
- eSIM provisioning statistics
- M2M device connection metrics
- AI service usage tracking
- Real-time performance monitoring

### Firebase Analytics
- User engagement tracking
- Performance monitoring
- Error reporting and logging

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

### Development Guidelines
- Follow PEP 8 for Python code
- Use TypeScript for frontend development
- Write comprehensive tests
- Update documentation for new features
- Follow semantic versioning

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Documentation
- **API Docs**: Available at `/docs` when running the FastAPI server
- **Firebase Console**: https://console.firebase.google.com/project/bamboo-reason-483913-i4

### Getting Help
- Create an issue on GitHub
- Check existing documentation
- Review the deployment logs

## 🎯 Roadmap

### Phase 1 (Current)
- ✅ Core platform architecture
- ✅ AI service integrations
- ✅ eSIM provisioning system
- ✅ M2M device management
- ✅ Web and GUI interfaces

### Phase 2 (Planned)
- 🔄 WebSocket real-time updates
- 🔄 Advanced analytics dashboard
- 🔄 Mobile application
- 🔄 Enterprise authentication
- 🔄 Multi-tenant support

### Phase 3 (Future)
- 📋 Machine learning insights
- 📋 Advanced automation workflows
- 📋 Third-party integrations
- 📋 Global eSIM marketplace

---

**Built with ❤️ by iGSIM AI Agent powered by eSIM Myanmar**

*Comprehensive AI Agent platform with eSIM AI Agent M2M and Smart Website services*