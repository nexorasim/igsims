import React from 'react';
import { Inter } from 'next/font/google';
import './globals.css';

const inter = Inter({ subsets: ['latin'] });

export const metadata = {
  title: 'iGSIM AI Agent powered by eSIM Myanmar',
  description: 'Comprehensive AI Agent platform with eSIM AI Agent M2M and Smart Website services',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <nav className="bg-white shadow-sm border-b">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between h-16">
              <div className="flex items-center">
                <h1 className="text-xl font-bold text-gray-900">
                  iGSIM AI Agent powered by eSIM Myanmar
                </h1>
              </div>
              <div className="flex items-center space-x-4">
                <a href="#services" className="text-gray-700 hover:text-gray-900">Services</a>
                <a href="#features" className="text-gray-700 hover:text-gray-900">Features</a>
                <a href="#contact" className="text-gray-700 hover:text-gray-900">Contact</a>
              </div>
            </div>
          </div>
        </nav>
        {children}
      </body>
    </html>
  );
}