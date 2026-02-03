import React, { useState } from 'react';
import axios from 'axios';

const Results = ({ payloads, fileInfo, onBack, onReset }) => {
  const [selectedPayload, setSelectedPayload] = useState(null);
  const [editingPayload, setEditingPayload] = useState(null);
  const [customPayload, setCustomPayload] = useState('');
  const [injecting, setInjecting] = useState(false);
  const [injectionResult, setInjectionResult] = useState(null);
  const [activeTab, setActiveTab] = useState('payloads');
  const [previewFile, setPreviewFile] = useState(null);
  const [editingPreview, setEditingPreview] = useState(false);
  const [previewContent, setPreviewContent] = useState('');
  const [originalContent, setOriginalContent] = useState('');

  const handleEditPayload = (payload, index) => {
    setEditingPayload(index);
    setCustomPayload(payload.payload);
  };

  const handleSavePayload = (index) => {
    payloads[index].payload = customPayload;
    setEditingPayload(null);
    setCustomPayload('');
  };

  const handleInjectPayload = async (payload) => {
    setInjecting(true);
    try {
      const formData = new FormData();
      formData.append('payload_type', payload.type);
      formData.append('payload', payload.payload);
      formData.append('collaborator', 'https://test.burpcollaborator.net');

      // Simulate injection process
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      const mockResult = {
        success: true,
        output_filename: `xxe_${Date.now()}_${fileInfo.name}`,
        modified_files: ['xl/workbook.xml', 'xl/sharedStrings.xml'],
        message: `Successfully injected XXE payload into 2 files`,
        download_url: `/api/download/xxe_${Date.now()}_${fileInfo.name}`,
        file_content: generateMockFileContent(payload)
      };

      setInjectionResult(mockResult);
      setActiveTab('results');
    } catch (error) {
      setInjectionResult({
        success: false,
        error: error.response?.data?.error || 'Failed to inject payload'
      });
    } finally {
      setInjecting(false);
    }
  };

  const generateMockFileContent = (payload) => {
    return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <!-- XXE Payload Injected -->
  ${payload.payload}
  <sheets>
    <sheet name="Sheet1" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>`;
  };

  const handlePreviewFile = (content, filename) => {
    setPreviewFile({ content, filename });
    setPreviewContent(content);
    setOriginalContent(content);
    setEditingPreview(false);
  };

  const handleSavePreview = () => {
    setPreviewFile({ ...previewFile, content: previewContent });
    setEditingPreview(false);
  };

  const highlightChanges = (original, modified) => {
    const originalLines = original.split('\n');
    const modifiedLines = modified.split('\n');
    const maxLines = Math.max(originalLines.length, modifiedLines.length);
    
    let result = [];
    for (let i = 0; i < maxLines; i++) {
      const origLine = originalLines[i] || '';
      const modLine = modifiedLines[i] || '';
      
      if (origLine !== modLine) {
        result.push(`<span class="bg-yellow-500/20 text-yellow-300">${modLine}</span>`);
      } else {
        result.push(modLine);
      }
    }
    return result.join('\n');
  };

  const handleDownloadFile = (filename) => {
    // Create a blob with the file content
    const blob = new Blob([injectionResult.file_content], { type: 'application/xml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
  };

  const getPayloadTypeColor = (type) => {
    const colors = {
      doctype: 'from-blue-500 to-blue-600',
      xinclude: 'from-green-500 to-green-600',
      dtd: 'from-yellow-500 to-yellow-600',
      svg: 'from-purple-500 to-purple-600'
    };
    return colors[type] || 'from-gray-500 to-gray-600';
  };

  const getPayloadTypeIcon = (type) => {
    switch (type) {
      case 'doctype':
        return '📄';
      case 'xinclude':
        return '🔗';
      case 'dtd':
        return '📋';
      case 'svg':
        return '🎨';
      default:
        return '⚡';
    }
  };

  return (
    <div className="glass rounded-3xl p-8 shadow-2xl border border-white/20 backdrop-blur-xl">
      <div className="flex items-center justify-between mb-8">
        <div className="flex items-center">
          <button
            onClick={onBack}
            className="mr-4 p-3 text-gray-400 hover:text-white transition-colors hover:bg-white/10 rounded-xl"
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 19l-7-7 7-7" />
            </svg>
          </button>
          <div>
            <h2 className="text-3xl font-bold gradient-text">Generated Payloads</h2>
            <p className="text-gray-300 text-lg">{payloads.length} payloads for {fileInfo?.name}</p>
          </div>
        </div>
        <button
          onClick={onReset}
          className="bg-gradient-to-r from-gray-600 to-gray-700 hover:from-gray-700 hover:to-gray-800 text-white px-6 py-3 rounded-xl transition-all duration-300 transform hover:scale-105 shadow-lg"
        >
          🔄 Start Over
        </button>
      </div>

      {/* Tabs */}
      <div className="flex space-x-2 mb-8">
        {[
          { id: 'payloads', label: `💥 Payloads (${payloads.length})`, count: payloads.length },
          { id: 'results', label: '📊 Injection Results', count: injectionResult ? 1 : 0 },
          { id: 'preview', label: '👁️ File Preview', count: previewFile ? 1 : 0 }
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-6 py-3 rounded-xl font-semibold transition-all duration-300 transform hover:scale-105 ${
              activeTab === tab.id
                ? 'bg-gradient-to-r from-blue-600 to-purple-600 text-white shadow-lg'
                : 'bg-gray-700/50 text-gray-300 hover:bg-gray-600/50'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Payloads Tab */}
      {activeTab === 'payloads' && (
        <div className="space-y-6">
          {payloads.map((payload, index) => (
            <div key={index} className="bg-gradient-to-r from-gray-800/30 to-gray-700/30 backdrop-blur-sm rounded-2xl border border-gray-600/50 overflow-hidden">
              <div className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center space-x-4">
                    <div className={`px-4 py-2 rounded-full bg-gradient-to-r ${getPayloadTypeColor(payload.type)} text-white font-semibold shadow-lg`}>
                      {getPayloadTypeIcon(payload.type)} {payload.type.toUpperCase()}
                    </div>
                    <h3 className="text-white font-bold text-xl">{payload.name}</h3>
                  </div>
                  <div className="flex space-x-3">
                    <button
                      onClick={() => handleEditPayload(payload, index)}
                      className="text-blue-400 hover:text-blue-300 transition-colors p-2 hover:bg-blue-500/10 rounded-lg"
                      title="Edit payload"
                    >
                      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                      </svg>
                    </button>
                    <button
                      onClick={() => copyToClipboard(payload.payload)}
                      className="text-green-400 hover:text-green-300 transition-colors p-2 hover:bg-green-500/10 rounded-lg"
                      title="Copy payload"
                    >
                      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                    </button>
                    <button
                      onClick={() => setSelectedPayload(selectedPayload === index ? null : index)}
                      className="text-gray-400 hover:text-white transition-colors p-2 hover:bg-white/10 rounded-lg"
                    >
                      <svg className={`w-5 h-5 transform transition-transform ${selectedPayload === index ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7" />
                      </svg>
                    </button>
                  </div>
                </div>
                
                <p className="text-gray-300 text-lg mb-4">{payload.description}</p>
                
                {selectedPayload === index && (
                  <div className="mt-6 space-y-4 animate-fadeIn">
                    {editingPayload === index ? (
                      <div className="space-y-4">
                        <div className="bg-gray-900/50 rounded-xl p-4 border border-gray-600">
                          <label className="block text-gray-300 text-sm font-semibold mb-2">Edit Payload:</label>
                          <textarea
                            value={customPayload}
                            onChange={(e) => setCustomPayload(e.target.value)}
                            className="w-full h-40 bg-gray-800 text-green-400 font-mono text-sm p-4 rounded-lg border border-gray-600 focus:border-blue-500 focus:outline-none resize-none"
                            placeholder="Enter your custom XXE payload..."
                          />
                        </div>
                        <div className="flex space-x-3">
                          <button
                            onClick={() => handleSavePayload(index)}
                            className="bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white px-6 py-2 rounded-lg transition-all duration-300 transform hover:scale-105"
                          >
                            💾 Save Changes
                          </button>
                          <button
                            onClick={() => setEditingPayload(null)}
                            className="bg-gradient-to-r from-gray-600 to-gray-700 hover:from-gray-700 hover:to-gray-800 text-white px-6 py-2 rounded-lg transition-all duration-300"
                          >
                            ❌ Cancel
                          </button>
                        </div>
                      </div>
                    ) : (
                      <div className="bg-gray-900/50 rounded-xl p-4 border border-gray-600">
                        <div className="flex items-center justify-between mb-3">
                          <span className="text-gray-300 font-semibold">💻 Payload Code</span>
                          <button
                            onClick={() => copyToClipboard(payload.payload)}
                            className="text-blue-400 hover:text-blue-300 text-sm font-medium"
                          >
                            📋 Copy
                          </button>
                        </div>
                        <pre className="text-green-400 text-sm overflow-x-auto whitespace-pre-wrap font-mono bg-black/30 p-4 rounded-lg">
                          {payload.payload}
                        </pre>
                      </div>
                    )}
                    
                    {editingPayload !== index && (
                      <button
                        onClick={() => handleInjectPayload(payload)}
                        disabled={injecting}
                        className="bg-gradient-to-r from-red-600 to-pink-600 hover:from-red-700 hover:to-pink-700 disabled:from-gray-600 disabled:to-gray-600 text-white font-bold py-3 px-8 rounded-xl transition-all duration-300 transform hover:scale-105 disabled:scale-100 shadow-lg"
                      >
                        {injecting ? (
                          <div className="flex items-center">
                            <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                            </svg>
                            🔄 Injecting...
                          </div>
                        ) : (
                          '💉 Inject into File'
                        )}
                      </button>
                    )}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Results Tab */}
      {activeTab === 'results' && (
        <div>
          {injectionResult ? (
            <div className={`rounded-2xl p-8 border-2 ${
              injectionResult.success 
                ? 'bg-gradient-to-r from-green-900/20 to-emerald-900/20 border-green-500/50' 
                : 'bg-gradient-to-r from-red-900/20 to-pink-900/20 border-red-500/50'
            } backdrop-blur-sm`}>
              <div className="flex items-center mb-6">
                <div className={`w-16 h-16 rounded-full flex items-center justify-center mr-4 ${
                  injectionResult.success ? 'bg-gradient-to-r from-green-500 to-emerald-500' : 'bg-gradient-to-r from-red-500 to-pink-500'
                } shadow-lg`}>
                  {injectionResult.success ? (
                    <svg className="w-8 h-8 text-white" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                    </svg>
                  ) : (
                    <svg className="w-8 h-8 text-white" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                    </svg>
                  )}
                </div>
                <div>
                  <h3 className={`text-2xl font-bold ${
                    injectionResult.success ? 'text-green-300' : 'text-red-300'
                  }`}>
                    {injectionResult.success ? '✅ Injection Successful!' : '❌ Injection Failed'}
                  </h3>
                  <p className={`text-lg ${
                    injectionResult.success ? 'text-green-400' : 'text-red-400'
                  }`}>
                    {injectionResult.message || injectionResult.error}
                  </p>
                </div>
              </div>

              {injectionResult.success && (
                <div className="space-y-6">
                  <div className="bg-gray-800/50 rounded-xl p-6 border border-gray-600/50">
                    <h4 className="text-white font-bold text-xl mb-4">📁 Output File</h4>
                    <div className="flex items-center justify-between bg-gray-900/50 rounded-lg p-4">
                      <div className="flex items-center space-x-3">
                        <div className="w-10 h-10 bg-gradient-to-r from-blue-500 to-purple-500 rounded-lg flex items-center justify-center">
                          <svg className="w-5 h-5 text-white" fill="currentColor" viewBox="0 0 20 20">
                            <path fillRule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" clipRule="evenodd" />
                          </svg>
                        </div>
                        <span className="text-gray-300 font-medium">{injectionResult.output_filename}</span>
                      </div>
                      <div className="flex space-x-3">
                        <button 
                          onClick={() => {
                            handlePreviewFile(injectionResult.file_content, injectionResult.output_filename);
                            setActiveTab('preview');
                          }}
                          className="bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white px-4 py-2 rounded-lg transition-all duration-300 transform hover:scale-105 shadow-lg"
                        >
                          👁️ Preview
                        </button>
                        <button 
                          onClick={() => handleDownloadFile(injectionResult.output_filename)}
                          className="bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white px-4 py-2 rounded-lg transition-all duration-300 transform hover:scale-105 shadow-lg"
                        >
                          💾 Download
                        </button>
                      </div>
                    </div>
                  </div>

                  <div className="bg-gray-800/50 rounded-xl p-6 border border-gray-600/50">
                    <h4 className="text-white font-bold text-xl mb-4">📝 Modified Files</h4>
                    <div className="space-y-3">
                      {injectionResult.modified_files?.map((file, index) => (
                        <div key={index} className="bg-gray-900/50 rounded-lg p-4 flex items-center justify-between">
                          <div className="flex items-center space-x-3">
                            <div className="w-8 h-8 bg-gradient-to-r from-yellow-500 to-orange-500 rounded-lg flex items-center justify-center">
                              <svg className="w-4 h-4 text-white" fill="currentColor" viewBox="0 0 20 20">
                                <path fillRule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" clipRule="evenodd" />
                              </svg>
                            </div>
                            <span className="text-gray-300">{file}</span>
                          </div>
                          <span className="text-green-400 text-sm font-medium">✅ Modified</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="text-center py-16">
              <div className="w-24 h-24 bg-gradient-to-r from-gray-600 to-gray-700 rounded-full flex items-center justify-center mx-auto mb-6">
                <svg className="w-12 h-12 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
              </div>
              <h3 className="text-gray-400 text-2xl font-bold mb-3">No Results Yet</h3>
              <p className="text-gray-500 text-lg">Select a payload and inject it to see results here</p>
            </div>
          )}
        </div>
      )}

      {/* Preview Tab */}
      {activeTab === 'preview' && (
        <div>
          {previewFile ? (
            <div className="bg-gray-800/50 rounded-2xl p-6 border border-gray-600/50">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-2xl font-bold text-white">👁️ File Preview: {previewFile.filename}</h3>
                <div className="flex space-x-3">
                  <button
                    onClick={() => setEditingPreview(!editingPreview)}
                    className={`px-4 py-2 rounded-lg transition-all duration-300 ${
                      editingPreview 
                        ? 'bg-gradient-to-r from-green-600 to-emerald-600 text-white' 
                        : 'bg-gradient-to-r from-blue-600 to-cyan-600 text-white'
                    }`}
                  >
                    {editingPreview ? '👁️ View' : '✏️ Edit'}
                  </button>
                  <button
                    onClick={() => setPreviewFile(null)}
                    className="text-gray-400 hover:text-red-400 transition-colors p-2 hover:bg-red-500/10 rounded-lg"
                  >
                    <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
                    </svg>
                  </button>
                </div>
              </div>
              
              {editingPreview ? (
                <div className="space-y-4">
                  <div className="bg-black/50 rounded-xl p-4 border border-gray-700">
                    <textarea
                      value={previewContent}
                      onChange={(e) => setPreviewContent(e.target.value)}
                      className="w-full h-96 bg-gray-900 text-green-400 font-mono text-sm p-4 rounded-lg border border-gray-600 focus:border-blue-500 focus:outline-none resize-none"
                      placeholder="Edit file content..."
                    />
                  </div>
                  <div className="flex space-x-3">
                    <button
                      onClick={handleSavePreview}
                      className="bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white px-6 py-2 rounded-lg transition-all duration-300 transform hover:scale-105"
                    >
                      💾 Save Changes
                    </button>
                    <button
                      onClick={() => {
                        setPreviewContent(originalContent);
                        setEditingPreview(false);
                      }}
                      className="bg-gradient-to-r from-gray-600 to-gray-700 hover:from-gray-700 hover:to-gray-800 text-white px-6 py-2 rounded-lg transition-all duration-300"
                    >
                      ❌ Cancel
                    </button>
                  </div>
                </div>
              ) : (
                <div className="bg-black/50 rounded-xl p-6 border border-gray-700">
                  <pre 
                    className="text-green-400 text-sm overflow-auto max-h-96 font-mono whitespace-pre-wrap"
                    dangerouslySetInnerHTML={{
                      __html: previewContent !== originalContent 
                        ? highlightChanges(originalContent, previewContent)
                        : previewContent
                    }}
                  />
                </div>
              )}
              
              <div className="mt-4 flex space-x-3">
                <button
                  onClick={() => copyToClipboard(previewContent)}
                  className="bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white px-4 py-2 rounded-lg transition-all duration-300"
                >
                  📋 Copy Content
                </button>
                <button
                  onClick={() => handleDownloadFile(previewFile.filename)}
                  className="bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white px-4 py-2 rounded-lg transition-all duration-300"
                >
                  💾 Download File
                </button>
              </div>
            </div>
          ) : (
            <div className="text-center py-16">
              <div className="w-24 h-24 bg-gradient-to-r from-gray-600 to-gray-700 rounded-full flex items-center justify-center mx-auto mb-6">
                <svg className="w-12 h-12 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                </svg>
              </div>
              <h3 className="text-gray-400 text-2xl font-bold mb-3">No File to Preview</h3>
              <p className="text-gray-500 text-lg">Inject a payload first, then click Preview to see the modified file</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default Results;