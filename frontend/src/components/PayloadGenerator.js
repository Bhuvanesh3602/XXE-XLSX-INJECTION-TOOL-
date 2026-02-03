import React, { useState } from 'react';
import axios from 'axios';

const PayloadGenerator = ({ fileInfo, onPayloadsGenerated, onError, onBack }) => {
  const [collaborator, setCollaborator] = useState('');
  const [targetUrl, setTargetUrl] = useState('');
  const [attackType, setAttackType] = useState('all');
  const [generating, setGenerating] = useState(false);

  const handleGenerate = async () => {
    if (!collaborator && !targetUrl) {
      onError('Please provide either a collaborator URL or target URL');
      return;
    }

    setGenerating(true);
    try {
      const response = await axios.post('http://localhost:5000/api/generate-payloads', {
        target_url: targetUrl,
        collaborator: collaborator,
        attack_type: attackType
      });

      onPayloadsGenerated(response.data.payloads);
    } catch (error) {
      onError(error.response?.data?.error || 'Failed to generate payloads');
    } finally {
      setGenerating(false);
    }
  };

  const attackTypes = [
    { value: 'all', label: 'All Payload Types', description: 'Generate all available XXE payloads' },
    { value: 'doctype', label: 'DOCTYPE Declarations', description: 'Basic XXE using DOCTYPE declarations' },
    { value: 'xinclude', label: 'XInclude Attacks', description: 'XML Inclusion based attacks' },
    { value: 'dtd', label: 'External DTD', description: 'External DTD based payloads' },
    { value: 'svg', label: 'SVG Based', description: 'SVG embedded XXE payloads' }
  ];

  return (
    <div className="bg-gray-800/50 backdrop-blur-sm rounded-xl p-8 border border-gray-700">
      <div className="flex items-center mb-6">
        <button
          onClick={onBack}
          className="mr-4 p-2 text-gray-400 hover:text-white transition-colors"
        >
          <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 19l-7-7 7-7" />
          </svg>
        </button>
        <div>
          <h2 className="text-2xl font-bold text-white">Generate XXE Payloads</h2>
          <p className="text-gray-400">Configure payload parameters for {fileInfo?.name}</p>
        </div>
      </div>

      {/* File Info */}
      <div className="bg-gray-700/30 rounded-lg p-4 mb-6">
        <div className="flex items-center">
          <div className="flex-shrink-0">
            {fileInfo?.isXlsx ? (
              <svg className="h-8 w-8 text-green-400" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" clipRule="evenodd" />
              </svg>
            ) : (
              <svg className="h-8 w-8 text-blue-400" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm3.293-7.707a1 1 0 011.414 0L9 10.586V3a1 1 0 112 0v7.586l1.293-1.293a1 1 0 111.414 1.414l-3 3a1 1 0 01-1.414 0l-3-3a1 1 0 010-1.414z" clipRule="evenodd" />
              </svg>
            )}
          </div>
          <div className="ml-3">
            <p className="text-white font-medium">{fileInfo?.name}</p>
            <p className="text-gray-400 text-sm">
              {fileInfo?.isZip ? 'ZIP Archive' : 'XLSX Spreadsheet'} • {(fileInfo?.size / 1024).toFixed(1)} KB
            </p>
          </div>
        </div>
      </div>

      {/* Configuration Form */}
      <div className="space-y-6">
        {/* URLs Section */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Collaborator URL
            </label>
            <input
              type="url"
              value={collaborator}
              onChange={(e) => setCollaborator(e.target.value)}
              placeholder="https://your-collaborator.burpcollaborator.net"
              className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
            <p className="text-gray-500 text-sm mt-1">For out-of-band attacks and data exfiltration</p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Target URL
            </label>
            <input
              type="text"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="file:///etc/passwd or http://internal.server/resource"
              className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
            <p className="text-gray-500 text-sm mt-1">Target file or URL for direct attacks</p>
          </div>
        </div>

        {/* Attack Type Selection */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-3">
            Attack Type
          </label>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {attackTypes.map((type) => (
              <div
                key={type.value}
                className={`relative cursor-pointer rounded-lg p-4 border-2 transition-all ${
                  attackType === type.value
                    ? 'border-blue-500 bg-blue-900/20'
                    : 'border-gray-600 bg-gray-700/30 hover:border-gray-500'
                }`}
                onClick={() => setAttackType(type.value)}
              >
                <div className="flex items-center">
                  <input
                    type="radio"
                    name="attackType"
                    value={type.value}
                    checked={attackType === type.value}
                    onChange={() => setAttackType(type.value)}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300"
                  />
                  <div className="ml-3">
                    <h3 className="text-white font-medium">{type.label}</h3>
                    <p className="text-gray-400 text-sm">{type.description}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Info Box */}
        <div className="bg-blue-900/20 border border-blue-500/30 rounded-lg p-4">
          <div className="flex items-start">
            <svg className="w-5 h-5 text-blue-400 mr-3 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
            </svg>
            <div>
              <h3 className="text-blue-300 font-medium mb-1">Payload Configuration Tips</h3>
              <ul className="text-blue-200 text-sm space-y-1">
                <li>• Use Burp Collaborator or similar for out-of-band testing</li>
                <li>• Target URLs can be files (file:///etc/passwd) or HTTP endpoints</li>
                <li>• "All Payload Types" generates comprehensive test cases</li>
                <li>• Ensure you have permission to test the target system</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Generate Button */}
        <div className="text-center">
          <button
            onClick={handleGenerate}
            disabled={generating || (!collaborator && !targetUrl)}
            className="bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 disabled:from-gray-600 disabled:to-gray-600 text-white font-medium py-3 px-8 rounded-lg transition-all duration-200 transform hover:scale-105 disabled:scale-100 disabled:cursor-not-allowed"
          >
            {generating ? (
              <div className="flex items-center">
                <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Generating Payloads...
              </div>
            ) : (
              <div className="flex items-center">
                <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
                Generate XXE Payloads
              </div>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};

export default PayloadGenerator;