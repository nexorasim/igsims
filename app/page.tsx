'use client'

import { useState, useEffect } from 'react'
import { ChevronRightIcon, CpuChipIcon, GlobeAltIcon, SparklesIcon } from '@heroicons/react/24/outline'

export default function HomePage() {
  const [isLoaded, setIsLoaded] = useState(false)

  useEffect(() => {
    setIsLoaded(true)
  }, [])

  return (
    <div className={`min-h-screen bg-gradient-to-br from-blue-50 via-white to-green-50 transition-opacity duration-1000 ${isLoaded ? 'opacity-100' : 'opacity-0'}`}>
      {/* Header */}
      <header className="bg-white/80 backdrop-blur-sm border-b border-gray-200 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center space-x-3">
              <div className="w-10 h-10 bg-gradient-to-r from-blue-600 to-green-600 rounded-lg flex items-center justify-center">
                <SparklesIcon className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-gray-900">iGSIM AI Agent</h1>
                <p className="text-sm text-gray-600">powered by eSIM Myanmar</p>
              </div>
            </div>
            <nav className="hidden md:flex space-x-8">
              <a href="#features" className="text-gray-700 hover:text-blue-600 transition-colors">Features</a>
              <a href="#services" className="text-gray-700 hover:text-blue-600 transition-colors">Services</a>
              <a href="#contact" className="text-gray-700 hover:text-blue-600 transition-colors">Contact</a>
            </nav>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="relative py-20 px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto">
          <div className="text-center animate-fade-in">
            <h1 className="text-4xl md:text-6xl font-bold text-gray-900 mb-6">
              <span className="bg-gradient-to-r from-blue-600 to-green-600 bg-clip-text text-transparent">
                iGSIM AI Agent
              </span>
              <br />
              <span className="text-2xl md:text-3xl text-gray-700">powered by eSIM Myanmar</span>
            </h1>
            <p className="text-xl text-gray-600 mb-8 max-w-3xl mx-auto">
              Comprehensive AI Agent platform featuring eSIM AI Agent M2M and Smart Website services 
              with cutting-edge technology and seamless integration.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <button className="bg-gradient-to-r from-blue-600 to-blue-700 text-white px-8 py-3 rounded-lg font-semibold hover:from-blue-700 hover:to-blue-800 transition-all duration-200 flex items-center justify-center">
                Get Started
                <ChevronRightIcon className="w-5 h-5 ml-2" />
              </button>
              <button className="border border-gray-300 text-gray-700 px-8 py-3 rounded-lg font-semibold hover:bg-gray-50 transition-colors">
                Learn More
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-20 bg-white/50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
              Advanced AI Agent Features
            </h2>
            <p className="text-xl text-gray-600 max-w-2xl mx-auto">
              Built with 2026 AI Agent standards and modern technology stack
            </p>
          </div>
          
          <div className="grid md:grid-cols-3 gap-8">
            <div className="bg-white rounded-xl p-8 shadow-sm border border-gray-100 hover:shadow-md transition-shadow animate-slide-up">
              <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center mb-6">
                <CpuChipIcon className="w-6 h-6 text-blue-600" />
              </div>
              <h3 className="text-xl font-semibold text-gray-900 mb-4">eSIM AI Agent M2M</h3>
              <p className="text-gray-600 mb-4">
                Advanced eSIM provisioning and M2M device management with AI-powered automation
              </p>
              <ul className="text-sm text-gray-500 space-y-2">
                <li>• Automated eSIM provisioning</li>
                <li>• M2M device management</li>
                <li>• Real-time monitoring</li>
                <li>• AI-powered optimization</li>
              </ul>
            </div>

            <div className="bg-white rounded-xl p-8 shadow-sm border border-gray-100 hover:shadow-md transition-shadow animate-slide-up" style={{animationDelay: '0.1s'}}>
              <div className="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center mb-6">
                <GlobeAltIcon className="w-6 h-6 text-green-600" />
              </div>
              <h3 className="text-xl font-semibold text-gray-900 mb-4">Smart Website Services</h3>
              <p className="text-gray-600 mb-4">
                Intelligent web services with modern UI/UX design and seamless integration
              </p>
              <ul className="text-sm text-gray-500 space-y-2">
                <li>• Modern responsive design</li>
                <li>• AI-powered features</li>
                <li>• Firebase integration</li>
                <li>• Real-time updates</li>
              </ul>
            </div>

            <div className="bg-white rounded-xl p-8 shadow-sm border border-gray-100 hover:shadow-md transition-shadow animate-slide-up" style={{animationDelay: '0.2s'}}>
              <div className="w-12 h-12 bg-purple-100 rounded-lg flex items-center justify-center mb-6">
                <SparklesIcon className="w-6 h-6 text-purple-600" />
              </div>
              <h3 className="text-xl font-semibold text-gray-900 mb-4">AI Integration</h3>
              <p className="text-gray-600 mb-4">
                Powered by Google Gemini, xai, and groq for comprehensive AI capabilities
              </p>
              <ul className="text-sm text-gray-500 space-y-2">
                <li>• Google Gemini API</li>
                <li>• xai integration</li>
                <li>• groq processing</li>
                <li>• MCP protocol support</li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* Services Section */}
      <section id="services" className="py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
              Our Services
            </h2>
            <p className="text-xl text-gray-600 max-w-2xl mx-auto">
              Comprehensive solutions for modern connectivity and AI-powered automation
            </p>
          </div>
          
          <div className="grid md:grid-cols-2 gap-12 items-center">
            <div>
              <h3 className="text-2xl font-bold text-gray-900 mb-6">Technology Stack</h3>
              <div className="space-y-4">
                <div className="flex items-center space-x-3">
                  <div className="w-2 h-2 bg-blue-600 rounded-full"></div>
                  <span className="text-gray-700">Python with PyQt/PySide GUI</span>
                </div>
                <div className="flex items-center space-x-3">
                  <div className="w-2 h-2 bg-green-600 rounded-full"></div>
                  <span className="text-gray-700">Next.js with Tailwind CSS</span>
                </div>
                <div className="flex items-center space-x-3">
                  <div className="w-2 h-2 bg-purple-600 rounded-full"></div>
                  <span className="text-gray-700">Google Cloud Platform & Firebase</span>
                </div>
                <div className="flex items-center space-x-3">
                  <div className="w-2 h-2 bg-orange-600 rounded-full"></div>
                  <span className="text-gray-700">Google Gemini, xai, groq APIs</span>
                </div>
              </div>
            </div>
            
            <div className="bg-gradient-to-br from-blue-50 to-green-50 rounded-2xl p-8">
              <h3 className="text-2xl font-bold text-gray-900 mb-6">Deployment</h3>
              <div className="space-y-4">
                <div className="bg-white rounded-lg p-4 shadow-sm">
                  <h4 className="font-semibold text-gray-900 mb-2">Firebase Hosting</h4>
                  <p className="text-sm text-gray-600">bamboo-reason-483913-i4.web.app</p>
                </div>
                <div className="bg-white rounded-lg p-4 shadow-sm">
                  <h4 className="font-semibold text-gray-900 mb-2">Auto Deployment</h4>
                  <p className="text-sm text-gray-600">git push origin main</p>
                </div>
                <div className="bg-white rounded-lg p-4 shadow-sm">
                  <h4 className="font-semibold text-gray-900 mb-2">Repository</h4>
                  <p className="text-sm text-gray-600">github.com/nexorasim/igsims</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-gray-900 text-white py-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <div className="flex items-center justify-center space-x-3 mb-4">
              <div className="w-8 h-8 bg-gradient-to-r from-blue-600 to-green-600 rounded-lg flex items-center justify-center">
                <SparklesIcon className="w-5 h-5 text-white" />
              </div>
              <span className="text-xl font-bold">iGSIM AI Agent powered by eSIM Myanmar</span>
            </div>
            <p className="text-gray-400 mb-4">
              Comprehensive AI Agent platform with eSIM AI Agent M2M and Smart Website services
            </p>
            <p className="text-sm text-gray-500">
              © 2026 iGSIM AI Agent powered by eSIM Myanmar. Licensed under Apache License 2.0
            </p>
          </div>
        </div>
      </footer>
    </div>
  )
}