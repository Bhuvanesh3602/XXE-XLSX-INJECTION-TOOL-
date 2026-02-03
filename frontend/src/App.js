import React, { useState } from 'react';
import FileUpload from './components/FileUpload';
import PayloadGenerator from './components/PayloadGenerator';
import Results from './components/Results';

function App() {
  const [currentStep, setCurrentStep] = useState('upload');
  const [fileInfo, setFileInfo] = useState(null);
  const [payloads, setPayloads] = useState([]);
  const [results, setResults] = useState(null);
  const [error, setError] = useState('');

  const handleFileUploaded = (info) => {
    setFileInfo(info);
    setCurrentStep('generate');
    setError('');
  };

  const handlePayloadsGenerated = (generatedPayloads) => {
    setPayloads(generatedPayloads);
    setCurrentStep('results');
  };

  const handleError = (errorMessage) => {
    setError(errorMessage);
  };

  const resetApp = () => {
    setCurrentStep('upload');
    setFileInfo(null);
    setPayloads([]);
    setResults(null);
    setError('');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 relative overflow-hidden">
      {/* Animated Background Elements */}
      <div className="absolute inset-0">
        <div className="absolute top-0 -left-4 w-72 h-72 bg-purple-300 rounded-full mix-blend-multiply filter blur-xl opacity-20 animate-blob"></div>
        <div className="absolute top-0 -right-4 w-72 h-72 bg-yellow-300 rounded-full mix-blend-multiply filter blur-xl opacity-20 animate-blob animation-delay-2000"></div>
        <div className="absolute -bottom-8 left-20 w-72 h-72 bg-pink-300 rounded-full mix-blend-multiply filter blur-xl opacity-20 animate-blob animation-delay-4000"></div>
      </div>

      <div className="relative z-10 container mx-auto px-4 py-8">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-r from-red-500 to-pink-500 rounded-full mb-6 shadow-2xl">
            <svg className="w-10 h-10 text-white" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M12.316 3.051a1 1 0 01.633 1.265l-4 12a1 1 0 11-1.898-.632l4-12a1 1 0 011.265-.633zM5.707 6.293a1 1 0 010 1.414L3.414 10l2.293 2.293a1 1 0 11-1.414 1.414l-3-3a1 1 0 010-1.414l3-3a1 1 0 011.414 0zm8.586 0a1 1 0 011.414 0l3 3a1 1 0 010 1.414l-3 3a1 1 0 11-1.414-1.414L16.586 10l-2.293-2.293a1 1 0 010-1.414z" clipRule="evenodd" />
            </svg>
          </div>
          
          <h1 className="text-6xl font-bold bg-gradient-to-r from-white via-purple-200 to-pink-200 bg-clip-text text-transparent mb-4 animate-pulse">
            XXE XLSX Tool
          </h1>
          <p className="text-xl text-gray-300 mb-8 max-w-2xl mx-auto leading-relaxed">
            Advanced security testing platform for XML External Entity vulnerabilities
          </p>
          
          {/* Security Warning */}
          <div className="mt-8 bg-gradient-to-r from-red-900/30 to-pink-900/30 backdrop-blur-sm border border-red-500/50 rounded-2xl p-6 max-w-3xl mx-auto shadow-2xl">
            <div className="flex items-center justify-center">
              <div className="flex-shrink-0">
                <div className="w-12 h-12 bg-red-500 rounded-full flex items-center justify-center animate-pulse">
                  <svg className="w-6 h-6 text-white" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                  </svg>
                </div>
              </div>
              <div className="ml-6">
                <h3 className="text-2xl font-bold text-red-300 mb-2">⚠️ AUTHORIZED TESTING ONLY</h3>
                <p className="text-red-200 text-lg">Use only on systems you own or have explicit permission to test</p>
              </div>
            </div>
          </div>
        </div>

        {/* Progress Steps */}
        <div className="flex justify-center mb-12">
          <div className="flex items-center space-x-8">
            {[
              { step: 'upload', number: 1, title: 'Upload File', icon: '📁' },
              { step: 'generate', number: 2, title: 'Generate Payloads', icon: '⚡' },
              { step: 'results', number: 3, title: 'Results', icon: '🎯' }
            ].map((item, index) => (
              <div key={item.step} className="flex items-center">
                <div className={`flex flex-col items-center transition-all duration-500 transform ${
                  currentStep === item.step ? 'scale-110' : 
                  (currentStep === 'generate' && item.step === 'upload') || 
                  (currentStep === 'results' && (item.step === 'upload' || item.step === 'generate')) ? 'scale-100' : 'scale-90'
                }`}>
                  <div className={`w-16 h-16 rounded-full flex items-center justify-center text-2xl font-bold transition-all duration-500 shadow-lg ${
                    currentStep === item.step 
                      ? 'bg-gradient-to-r from-blue-500 to-purple-500 text-white shadow-blue-500/50' 
                      : (currentStep === 'generate' && item.step === 'upload') || 
                        (currentStep === 'results' && (item.step === 'upload' || item.step === 'generate'))
                      ? 'bg-gradient-to-r from-green-500 to-emerald-500 text-white shadow-green-500/50'
                      : 'bg-gray-700 text-gray-400 shadow-gray-700/50'
                  }`}>
                    {(currentStep === 'generate' && item.step === 'upload') || 
                     (currentStep === 'results' && (item.step === 'upload' || item.step === 'generate')) ? '✓' : item.icon}
                  </div>
                  <span className={`mt-3 font-semibold transition-colors duration-300 ${
                    currentStep === item.step ? 'text-blue-300' : 
                    (currentStep === 'generate' && item.step === 'upload') || 
                    (currentStep === 'results' && (item.step === 'upload' || item.step === 'generate')) ? 'text-green-300' : 'text-gray-500'
                  }`}>
                    {item.title}
                  </span>
                </div>
                
                {index < 2 && (
                  <div className={`w-16 h-1 mx-4 rounded-full transition-all duration-500 ${
                    (currentStep === 'generate' && item.step === 'upload') || 
                    (currentStep === 'results' && item.step !== 'results')
                      ? 'bg-gradient-to-r from-green-500 to-emerald-500 shadow-lg shadow-green-500/50'
                      : 'bg-gray-600'
                  }`}></div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Error Display */}
        {error && (
          <div className="max-w-2xl mx-auto mb-8 animate-shake">
            <div className="bg-gradient-to-r from-red-900/50 to-pink-900/50 backdrop-blur-sm border border-red-500/50 rounded-2xl p-6 shadow-2xl">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <div className="w-10 h-10 bg-red-500 rounded-full flex items-center justify-center">
                    <svg className="w-5 h-5 text-white" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                    </svg>
                  </div>
                </div>
                <div className="ml-4">
                  <h3 className="text-red-300 font-semibold text-lg">Error</h3>
                  <p className="text-red-200">{error}</p>
                </div>
                <button 
                  onClick={() => setError('')}
                  className="ml-auto text-red-300 hover:text-red-100 transition-colors"
                >
                  <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
                  </svg>
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Main Content */}
        <div className="max-w-6xl mx-auto">
          <div className="transition-all duration-700 ease-in-out">
            {currentStep === 'upload' && (
              <div className="animate-fadeIn">
                <FileUpload 
                  onFileUploaded={handleFileUploaded}
                  onError={handleError}
                />
              </div>
            )}
            
            {currentStep === 'generate' && (
              <div className="animate-slideInRight">
                <PayloadGenerator
                  fileInfo={fileInfo}
                  onPayloadsGenerated={handlePayloadsGenerated}
                  onError={handleError}
                  onBack={() => setCurrentStep('upload')}
                />
              </div>
            )}
            
            {currentStep === 'results' && (
              <div className="animate-slideInUp">
                <Results
                  payloads={payloads}
                  fileInfo={fileInfo}
                  onBack={() => setCurrentStep('generate')}
                  onReset={resetApp}
                />
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;