'use client';

import { useState, FormEvent } from 'react';
// Remove unused Image import if not being used
// import Image from 'next/image';

// Define types based on the backend API response
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

type VulnerabilityType = {
  test_name: string;
  severity: Severity;
  description: string;
  evidence?: Record<string, unknown>; // Change from 'any' to this
  recommendation: string;
};

type TestResultType = {
  status: string;
  vulnerabilities: VulnerabilityType[];
};

type ScanResultsType = {
    url: string;
    results: {
        [key: string]: TestResultType;
    }
};

// Enhanced vulnerability component with better styling
const Vulnerability = ({ vulnerability }: { vulnerability: VulnerabilityType }) => {
  const severityStyles = {
    critical: { 
      border: 'border-red-500/30', 
      bg: 'bg-red-500/10', 
      text: 'text-red-400',
      icon: '',
      badge: 'bg-red-500/20 text-red-400 border-red-500/30'
    },
    high: { 
      border: 'border-orange-500/30', 
      bg: 'bg-orange-500/10', 
      text: 'text-orange-400',
      icon: '',
      badge: 'bg-orange-500/20 text-orange-400 border-orange-500/30'
    },
    medium: { 
      border: 'border-yellow-500/30', 
      bg: 'bg-yellow-500/10', 
      text: 'text-yellow-400',
      icon: '',
      badge: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
    },
    low: { 
      border: 'border-blue-500/30', 
      bg: 'bg-blue-500/10', 
      text: 'text-blue-400',
      icon: '',
      badge: 'bg-blue-500/20 text-blue-400 border-blue-500/30'
    },
    info: { 
      border: 'border-gray-500/30', 
      bg: 'bg-gray-500/10', 
      text: 'text-gray-400',
      icon: '⚪',
      badge: 'bg-gray-500/20 text-gray-400 border-gray-500/30'
    },
  };

  const styles = severityStyles[vulnerability.severity] || severityStyles.info;

  return (
    <div className={`${styles.border} ${styles.bg} p-6 rounded-xl mb-4 border backdrop-blur-sm transition-all duration-200 hover:scale-[1.02]`}>
      <div className="flex items-start gap-3">
        <span className="text-2xl">{styles.icon}</span>
        <div className="flex-1">
          <div className="flex items-center gap-3 mb-3">
            <h4 className={`font-bold text-lg ${styles.text}`}>{vulnerability.test_name}</h4>
            <span className={`px-3 py-1 rounded-full text-xs font-semibold border ${styles.badge}`}>
              {vulnerability.severity.toUpperCase()}
            </span>
          </div>
          <p className="text-gray-300 mb-4 leading-relaxed">{vulnerability.description}</p>
          
          {/* Evidence Section */}
          {vulnerability.evidence && (
            <div className="bg-gray-800/50 p-4 rounded-lg border border-gray-700/50 mb-4">
              <h5 className="font-semibold text-teal-400 mb-2">Evidence:</h5>
              <div className="text-sm text-gray-300 space-y-2">
                {typeof vulnerability.evidence === 'object' ? (
                  Object.entries(vulnerability.evidence).map(([key, value]) => (
                    <div key={key} className="flex">
                      <span className="font-medium text-gray-400 w-24 flex-shrink-0">{key}:</span>
                      <span className="text-gray-300 break-all">
                        {typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value)}
                      </span>
                    </div>
                  ))
                ) : (
                  <span className="text-gray-300">{String(vulnerability.evidence)}</span>
                )}
              </div>
            </div>
          )}
          
          <div className="bg-gray-900/50 p-4 rounded-lg border border-gray-700/50">
            <p className="text-sm text-gray-400">
              <span className="font-semibold text-teal-400">Recommendation:</span> {vulnerability.recommendation}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const getHighestSeverity = (vulnerabilities: VulnerabilityType[]): Severity | null => {
  if (!vulnerabilities || vulnerabilities.length === 0) return null;
  for (const severity of severityOrder) {
    if (vulnerabilities.some(v => v.severity === severity)) return severity;
  }
  return 'info';
};

// Enhanced test result component
const TestResult = ({ testName, result }: { testName: string, result: TestResultType }) => {
    const isFail = result.status === 'fail';
    const highestSeverity = isFail ? getHighestSeverity(result.vulnerabilities) : null;

    const statusStyles = {
      critical: 'text-red-400 bg-red-500/10 border-red-500/30',
      high: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
      medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
      low: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
      info: 'text-gray-400 bg-gray-500/10 border-gray-500/30',
      pass: 'text-green-400 bg-green-500/10 border-green-500/30',
    };
    
    const statusColor = isFail ? (statusStyles[highestSeverity || 'info']) : statusStyles.pass;

    return (
        <div className="mb-8 p-6 rounded-xl bg-gray-800/30 border border-gray-700/50 backdrop-blur-sm">
            <div className="flex items-center justify-between mb-4">
                <h3 className="text-xl font-semibold text-gray-200">{testName}</h3>
                <span className={`px-4 py-2 rounded-full text-sm font-semibold border ${statusColor}`}>
                    {result.status.toUpperCase()}
                </span>
            </div>
            {isFail && result.vulnerabilities.map((vuln, index) => (
                <Vulnerability key={index} vulnerability={vuln} />
            ))}
            {!isFail && (
                <div className="flex items-center gap-3 p-4 bg-green-500/10 border border-green-500/30 rounded-lg">
                    <span className="text-2xl">✅</span>
                    <p className="text-green-400 font-medium">No vulnerabilities found.</p>
                </div>
            )}
        </div>
    );
};

export default function Home() {
  const [url, setUrl] = useState('');
  const [results, setResults] = useState<ScanResultsType | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const handleScan = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setIsLoading(true);
    setResults(null);
    setError('');

    try {
      const response = await fetch('https://sealion-backend.onrender.com/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      setResults(data);
    } catch (err) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('An unexpected error occurred');
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-black">
      <div className="absolute inset-0 bg-[url('data:image/svg+xml,%3Csvg%20width%3D%2260%22%20height%3D%2260%22%20viewBox%3D%220%200%2060%2060%22%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%3E%3Cg%20fill%3D%22none%22%20fill-rule%3D%22evenodd%22%3E%3Cg%20fill%3D%22%239C92AC%22%20fill-opacity%3D%220.05%22%3E%3Ccircle%20cx%3D%2230%22%20cy%3D%2230%22%20r%3D%222%22/%3E%3C/g%3E%3C/g%3E%3C/svg%3E')] opacity-20"></div>
      <div className="relative flex min-h-screen flex-col items-center p-8">
        <div className="z-10 w-full max-w-6xl items-center justify-center text-sm flex flex-col">
          {/* Header Section */}
          <div className="text-center mb-12">
            <div className="flex justify-center mb-6">
            </div>
            <h1 className="text-6xl font-bold mb-6 bg-gradient-to-r from-teal-400 via-blue-500 to-purple-600 bg-clip-text text-transparent">
              SeaLion
            </h1>
            <p className="text-xl text-gray-300 mb-2 font-medium">
              Basic Security Scanner
            </p>
            <p className="text-lg text-gray-400 max-w-2xl mx-auto">
              Enter a URL to scan for modern web application vulnerabilities with our basic security analysis engine.
            </p>
          </div>
          
          {/* Scan Form */}
          <div className="w-full max-w-3xl mb-12">
            <form onSubmit={handleScan} className="relative">
              <div className="relative group">
                <div className="absolute inset-0 bg-gradient-to-r from-teal-500 to-blue-500 rounded-2xl blur opacity-20 group-hover:opacity-30 transition duration-300"></div>
                <div className="relative flex flex-col sm:flex-row items-stretch sm:items-center bg-gray-800/50 backdrop-blur-sm border border-gray-700/50 rounded-2xl p-2 shadow-2xl">
                  <input
                    className="flex-1 bg-transparent border-none text-gray-200 placeholder-gray-500 px-6 py-4 text-lg focus:outline-none focus:ring-0"
                    type="url"
                    placeholder="https://example.com"
                    aria-label="URL to scan"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    required
                  />
                  <button
                    className="bg-gradient-to-r from-teal-500 to-blue-500 hover:from-teal-600 hover:to-blue-600 text-white px-8 py-4 rounded-xl font-semibold text-lg transition-all duration-200 transform hover:scale-105 shadow-lg disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none mt-2 sm:mt-0"
                    type="submit"
                    disabled={isLoading}
                  >
                    {isLoading ? (
                      <div className="flex items-center gap-2">
                        <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                        Scanning...
                      </div>
                    ) : (
                      'Scan Now'
                    )}
                  </button>
                </div>
              </div>
            </form>
          </div>

          {/* Error Display */}
          {error && (
            <div className="w-full max-w-3xl mb-8">
              <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 text-red-400">
                <div className="flex items-center gap-3">
                  <span className="text-xl">⚠️</span>
                  <span className="font-medium">Error: {error}</span>
                </div>
              </div>
            </div>
          )}
          
          {/* Results Section */}
          {results && (
            <div className="w-full max-w-5xl">
              <div className="bg-gray-800/30 backdrop-blur-sm border border-gray-700/50 rounded-2xl p-8 shadow-2xl">
                <div className="flex items-center justify-between mb-8 pb-4 border-b border-gray-700/50">
                  <div>
                    <h2 className="text-3xl font-bold text-gray-200 mb-2">Security Scan Report</h2>
                    <p className="text-gray-400">Analysis completed for:</p>
                    <p className="text-teal-400 font-mono text-lg">{results.url}</p>
                  </div>
                  <div className="text-right">
                    <div className="text-2xl">🔒</div>
                    <p className="text-sm text-gray-400">SeaLion Security</p>
                  </div>
                </div>
                
                <div className="space-y-6">
                  {Object.entries(results.results)
                    .filter(([, result]) => result.status !== 'not_tested')
                    .map(([testName, result]) => (
                      <TestResult key={testName} testName={testName} result={result} />
                ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
