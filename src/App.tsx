import React, { useState } from 'react';
import { FileUpload } from './components/FileUpload';
import { FileAnalyzer } from './components/FileAnalyzer';
import { Shield, Cpu, Database } from 'lucide-react';

interface AnalyzedFile {
  id: string;
  file: File;
}

function App() {
  const [analyzedFiles, setAnalyzedFiles] = useState<AnalyzedFile[]>([]);

  const handleFileSelect = (files: File[]) => {
    const newFiles = files.map(file => ({
      id: `${file.name}-${Date.now()}-${Math.random()}`,
      file
    }));
    
    setAnalyzedFiles(prev => [...prev, ...newFiles]);
  };

  const handleRemoveFile = (id: string) => {
    setAnalyzedFiles(prev => prev.filter(f => f.id !== id));
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-cyan-50">
      {/* Header */}
      <header className="bg-white/80 backdrop-blur-sm border-b border-gray-200 sticky top-0 z-10">
        <div className="container mx-auto px-4 py-6">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-gradient-to-r from-blue-600 to-cyan-600 rounded-lg">
              <Shield className="w-8 h-8 text-white" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-gray-900">Binary File Analyzer</h1>
              <p className="text-gray-600">Advanced analysis and hash calculation for executable files</p>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-8">
        {/* Features Banner */}
        <div className="mb-8 grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-white/60 backdrop-blur-sm rounded-lg p-4 border border-gray-200">
            <div className="flex items-center space-x-3">
              <Cpu className="w-6 h-6 text-blue-600" />
              <div>
                <h3 className="font-semibold text-gray-900">Hash Calculation</h3>
                <p className="text-sm text-gray-600">SHA-256 cryptographic hash</p>
              </div>
            </div>
          </div>
          
          <div className="bg-white/60 backdrop-blur-sm rounded-lg p-4 border border-gray-200">
            <div className="flex items-center space-x-3">
              <Database className="w-6 h-6 text-cyan-600" />
              <div>
                <h3 className="font-semibold text-gray-900">File Analysis</h3>
                <p className="text-sm text-gray-600">PE, ELF, Mach-O formats</p>
              </div>
            </div>
          </div>
          
          <div className="bg-white/60 backdrop-blur-sm rounded-lg p-4 border border-gray-200">
            <div className="flex items-center space-x-3">
              <Shield className="w-6 h-6 text-green-600" />
              <div>
                <h3 className="font-semibold text-gray-900">.NET Detection</h3>
                <p className="text-sm text-gray-600">Assembly identification</p>
              </div>
            </div>
          </div>
        </div>

        {/* Upload Section */}
        {analyzedFiles.length === 0 && (
          <div className="mb-8">
            <FileUpload onFileSelect={handleFileSelect} />
          </div>
        )}

        {/* Quick Upload for Additional Files */}
        {analyzedFiles.length > 0 && (
          <div className="mb-8">
            <div className="bg-white/60 backdrop-blur-sm rounded-lg p-4 border border-gray-200">
              <h2 className="text-lg font-semibold text-gray-900 mb-4">Add More Files</h2>
              <FileUpload onFileSelect={handleFileSelect} />
            </div>
          </div>
        )}

        {/* Analysis Results */}
        {analyzedFiles.length > 0 && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <h2 className="text-2xl font-bold text-gray-900">
                Analysis Results ({analyzedFiles.length})
              </h2>
              <button
                onClick={() => setAnalyzedFiles([])}
                className="px-4 py-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors duration-200"
              >
                Clear All
              </button>
            </div>
            
            <div className="grid grid-cols-1 gap-6">
              {analyzedFiles.map(({ id, file }) => (
                <FileAnalyzer
                  key={id}
                  file={file}
                  onRemove={() => handleRemoveFile(id)}
                />
              ))}
            </div>
          </div>
        )}

        {/* Info Section */}
        <div className="mt-12 bg-white/60 backdrop-blur-sm rounded-lg p-6 border border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">About This Tool</h3>
          <div className="prose prose-gray max-w-none">
            <p className="text-gray-700 mb-4">
              This binary file analyzer provides comprehensive analysis of executable files and other binary formats. 
              All processing is performed client-side in your browser for maximum security and privacy.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
              <div>
                <h4 className="font-semibold text-gray-900 mb-2">Current Features:</h4>
                <ul className="space-y-1 text-gray-600">
                  <li>• Cryptographic hash calculation (SHA-256)</li>
                  <li>• PE, ELF, and Mach-O file format detection</li>
                  <li>• .NET assembly identification</li>
                  <li>• Architecture and compilation info</li>
                  <li>• File metadata extraction</li>
                  <li>• Results export to JSON</li>
                </ul>
              </div>
              <div>
                <h4 className="font-semibold text-gray-900 mb-2">Supported File Types:</h4>
                <ul className="space-y-1 text-gray-600">
                  <li>• Windows PE files (.exe, .dll)</li>
                  <li>• Linux ELF executables</li>
                  <li>• macOS Mach-O binaries</li>
                  <li>• .NET assemblies</li>
                  <li>• Any binary file format</li>
                  <li>• Multiple file analysis</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="bg-white/60 backdrop-blur-sm border-t border-gray-200 mt-12">
        <div className="container mx-auto px-4 py-6">
          <div className="text-center text-gray-600">
            <p className="mb-2">Binary File Analyzer - Secure client-side file analysis</p>
            <p className="text-sm">
              © {new Date().getFullYear()} PetiKVX. All rights reserved.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;