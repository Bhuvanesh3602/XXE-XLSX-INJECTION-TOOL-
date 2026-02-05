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
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-red-900 relative overflow-hidden">
      {/* Matrix Rain Effect */}
      <div className="absolute inset-0 opacity-10">
        <div className="matrix-rain"></div>
      </div>

      {/* Animated Particles */}
      <div className="absolute inset-0">
        {[...Array(20)].map((_, i) => (
          <div
            key={i}
            className="absolute w-2 h-2 bg-red-500 rounded-full animate-float"
            style={{
              left: `${Math.random() * 100}%`,
              top: `${Math.random() * 100}%`,
              animationDelay: `${Math.random() * 5}s`,
              animationDuration: `${3 + Math.random() * 4}s`
            }}
          ></div>
        ))}
      </div>

      <div className="relative z-10 container mx-auto px-4 py-8">
        {/* Cyberpunk Header */}
        <div className="text-center mb-12">
          <div className="relative inline-block mb-8">
            <div className="absolute inset-0 bg-red-500 blur-xl opacity-50 animate-pulse"></div>
            <div className="relative bg-gradient-to-r from-red-600 via-pink-600 to-red-600 p-6 rounded-2xl border border-red-400 shadow-2xl">
              <div className="flex items-center justify-center space-x-4">
                <div className="w-16 h-16 bg-black rounded-full flex items-center justify-center border-2 border-red-400">
                  <svg className="w-8 h-8 text-red-400" fill="currentColor" viewBox="0 0 20 20">
                    <path d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H4a1 1 0 01-1-1v-6zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z" />
                  </svg>
                </div>
                <div>
                  <h1 className="text-5xl font-bold text-white font-mono tracking-wider">
                    XXE <span className="text-red-300">INJECTION</span> TOOL
                  </h1>
                  <div className="text-red-200 text-lg font-mono mt-2 tracking-widest">
                    [ SECURITY TESTING PLATFORM ]
                  </div>
                </div>
              </div>
            </div>
          </div>
          
          <div className="bg-gradient-to-r from-red-900/20 via-black/40 to-red-900/20 backdrop-blur-sm border border-red-500/30 rounded-xl p-6 max-w-4xl mx-auto">
            <p className="text-gray-300 text-xl leading-relaxed font-mono">
              Advanced XML External Entity vulnerability testing framework
            </p>
          </div>
          
          {/* Glitch Warning */}
          <div className="mt-8 relative">
            <div className="absolute inset-0 bg-red-500 blur-lg opacity-20 animate-pulse"></div>
            <div className="relative bg-gradient-to-r from-red-900/50 via-black/70 to-red-900/50 backdrop-blur-sm border-2 border-red-500 rounded-xl p-6 max-w-3xl mx-auto shadow-2xl">
              <div className="flex items-center justify-center space-x-6">
                <div className="w-16 h-16 bg-red-500 rounded-full flex items-center justify-center animate-bounce">
                  <svg className="w-8 h-8 text-white" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                  </svg>
                </div>
                <div className="text-left">
                  <h3 className="text-3xl font-bold text-red-300 font-mono mb-2 glitch" data-text="AUTHORIZED ACCESS ONLY">
                    AUTHORIZED ACCESS ONLY
                  </h3>
                  <p className="text-red-200 text-lg font-mono">Use only on systems you own or have explicit permission to test</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Cyberpunk Progress Steps */}
        <div className="flex justify-center mb-12">
          <div className="bg-black/50 backdrop-blur-sm border border-red-500/30 rounded-2xl p-8 shadow-2xl">
            <div className="flex items-center space-x-12">
              {[
                { step: 'upload', number: 1, title: 'UPLOAD', icon: '📁', color: 'from-blue-500 to-cyan-500' },
                { step: 'generate', number: 2, title: 'GENERATE', icon: '⚡', color: 'from-yellow-500 to-orange-500' },
                { step: 'results', number: 3, title: 'RESULTS', icon: '🎯', color: 'from-green-500 to-emerald-500' }
              ].map((item, index) => (
                <div key={item.step} className="flex items-center">
                  <div className={`flex flex-col items-center transition-all duration-500 transform ${
                    currentStep === item.step ? 'scale-110' : 'scale-100'
                  }`}>
                    <div className={`relative w-20 h-20 rounded-xl flex items-center justify-center text-2xl font-bold transition-all duration-500 border-2 ${
                      currentStep === item.step 
                        ? `bg-gradient-to-r ${item.color} text-white border-white shadow-lg shadow-current/50 animate-pulse` 
                        : (currentStep === 'generate' && item.step === 'upload') || 
                          (currentStep === 'results' && (item.step === 'upload' || item.step === 'generate'))
                        ? 'bg-gradient-to-r from-green-500 to-emerald-500 text-white border-green-400 shadow-lg shadow-green-500/50'
                        : 'bg-gray-800 text-gray-400 border-gray-600'
                    }`}>
                      <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent animate-shimmer"></div>
                      <span className="relative z-10">
                        {(currentStep === 'generate' && item.step === 'upload') || 
                         (currentStep === 'results' && (item.step === 'upload' || item.step === 'generate')) ? '✓' : item.icon}
                      </span>
                    </div>
                    <div className={`mt-4 font-mono font-bold text-sm tracking-wider transition-colors duration-300 ${
                      currentStep === item.step ? 'text-white' : 
                      (currentStep === 'generate' && item.step === 'upload') || 
                      (currentStep === 'results' && (item.step === 'upload' || item.step === 'generate')) ? 'text-green-300' : 'text-gray-500'
                    }`}>
                      {item.title}
                    </div>
                    <div className={`w-2 h-2 rounded-full mt-2 transition-all duration-300 ${
                      currentStep === item.step ? 'bg-red-500 animate-ping' : 'bg-gray-600'
                    }`}></div>
                  </div>
                  
                  {index < 2 && (
                    <div className="flex flex-col items-center mx-8">
                      <div className={`w-20 h-1 rounded-full transition-all duration-500 ${
                        (currentStep === 'generate' && item.step === 'upload') || 
                        (currentStep === 'results' && item.step !== 'results')
                          ? 'bg-gradient-to-r from-green-500 to-emerald-500 shadow-lg shadow-green-500/50'
                          : 'bg-gray-600'
                      }`}></div>
                      <div className="text-gray-500 text-xs font-mono mt-2">NEXT</div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Enhanced Error Display */}
        {error && (
          <div className="max-w-2xl mx-auto mb-8 animate-shake">
            <div className="relative">
              <div className="absolute inset-0 bg-red-500 blur-lg opacity-30 animate-pulse"></div>
              <div className="relative bg-gradient-to-r from-red-900/80 via-black/80 to-red-900/80 backdrop-blur-sm border-2 border-red-500 rounded-xl p-6 shadow-2xl">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <div className="w-12 h-12 bg-red-500 rounded-full flex items-center justify-center animate-bounce">
                      <svg className="w-6 h-6 text-white" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                      </svg>
                    </div>
                  </div>
                  <div className="ml-6 flex-1">
                    <h3 className="text-red-300 font-bold text-xl font-mono">SYSTEM ERROR</h3>
                    <p className="text-red-200 font-mono">{error}</p>
                  </div>
                  <button 
                    onClick={() => setError('')}
                    className="ml-4 text-red-300 hover:text-red-100 transition-colors p-2 rounded-lg hover:bg-red-500/20"
                  >
                    <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
                    </svg>
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Main Content with Enhanced Transitions */}
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