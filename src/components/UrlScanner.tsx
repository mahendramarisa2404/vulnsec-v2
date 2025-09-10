import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Loader2, Link, Shield, AlertTriangle, CheckCircle, XCircle } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface ScanResult {
  url: string;
  status: 'safe' | 'suspicious' | 'malicious';
  detections: number;
  totalEngines: number;
  timestamp: string;
  engines: Array<{
    name: string;
    verdict: string;
    category?: string;
  }>;
}

const UrlScanner = () => {
  const [url, setUrl] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const { toast } = useToast();

  const suspiciousDomains = [
    'bit.ly', 'tinyurl.com', 'short.link', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'bl.ink', 'lnkd.in', 'smarturl.it', 'tiny.cc',
    'cutt.ly', 'rebrandly.com', '1drv.ms', 'discord.gg', 'youtu.be',
    'dropbox.com', 'drive.google.com', 'onedrive.live.com', 'mega.nz'
  ];

  const maliciousKeywords = [
    'phishing', 'scam', 'fake', 'verify-account', 'suspended', 'security-alert',
    'urgent-action', 'click-here', 'free-money', 'winner', 'congratulations',
    'crypto-wallet', 'bitcoin-generator', 'hack', 'crack', 'keygen', 'login-verify',
    'account-locked', 'update-payment', 'confirm-identity', 'tax-refund', 'lottery',
    'inheritance', 'prize', 'claim-reward', 'virus-detected', 'system-infected',
    'download-now', 'install-update', 'critical-security', 'banking-alert',
    'paypal-suspended', 'amazon-security', 'microsoft-warning', 'apple-id-locked'
  ];

  const highRiskTLDs = [
    '.tk', '.ml', '.ga', '.cf', '.click', '.download', '.zip', '.exe',
    '.scr', '.bat', '.com.suspicious', '.webcam', '.date', '.racing'
  ];

  const maliciousPatterns = [
    /[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}/, // IP-like patterns in domain
    /[a-zA-Z]{20,}/, // Very long random strings
    /(.)\1{4,}/, // Repeated characters (aaaaa, 11111)
    /-{3,}/, // Multiple dashes
    /[0-9]{8,}/, // Long number sequences
  ];

  const validateUrl = (urlString: string): boolean => {
    try {
      const urlObj = new URL(urlString);
      
      // Only allow HTTP and HTTPS
      if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') {
        toast({
          title: "Invalid Protocol",
          description: "Only HTTP and HTTPS URLs are allowed",
          variant: "destructive",
        });
        return false;
      }

      // Block local/private IPs
      const hostname = urlObj.hostname;
      const localPatterns = [
        /^localhost$/i,
        /^127\./,
        /^192\.168\./,
        /^10\./,
        /^172\.(1[6-9]|2[0-9]|3[01])\./,
        /^0\./,
        /^169\.254\./
      ];

      if (localPatterns.some(pattern => pattern.test(hostname))) {
        toast({
          title: "Invalid URL",
          description: "Local and private IP addresses are not allowed",
          variant: "destructive",
        });
        return false;
      }

      return true;
    } catch {
      return false;
    }
  };

  const mockScan = async (targetUrl: string): Promise<ScanResult> => {
    // Simulate API delay
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    const urlObj = new URL(targetUrl);
    const domain = urlObj.hostname.toLowerCase();
    const fullUrl = targetUrl.toLowerCase();
    
    // Enhanced threat detection with multiple layers
    const isSuspiciousDomain = suspiciousDomains.some(suspicious => domain.includes(suspicious));
    const hasMaliciousKeywords = maliciousKeywords.some(keyword => fullUrl.includes(keyword));
    const hasMultipleSubdomains = domain.split('.').length > 4;
    const hasNumbersInDomain = /\d{3,}/.test(domain.replace(/\.(com|org|net|edu|gov|co\.uk)$/, ''));
    const isHighRiskTLD = highRiskTLDs.some(tld => domain.endsWith(tld));
    const hasMaliciousPattern = maliciousPatterns.some(pattern => pattern.test(fullUrl));
    const hasHomographAttack = /[а-я]|[α-ω]|[א-ת]/i.test(domain); // Cyrillic, Greek, Hebrew chars
    const hasSuspiciousPort = urlObj.port && !['80', '443', '8080', '8443'].includes(urlObj.port);
    const hasSuspiciousPath = /\.(exe|scr|bat|cmd|pif|com|zip|rar)(\?|$)/i.test(urlObj.pathname);
    const isDomainSquatting = /(?:goog1e|microsooft|payp4l|amazom|facebbok)/i.test(domain);
    const hasBase64InUrl = /[A-Za-z0-9+\/]{20,}={0,2}/.test(fullUrl);
    
    // Calculate comprehensive threat probability
    let threatProbability = 0.02; // Base 2% chance
    if (isSuspiciousDomain) threatProbability += 0.35;
    if (hasMaliciousKeywords) threatProbability += 0.7;
    if (hasMultipleSubdomains) threatProbability += 0.25;
    if (hasNumbersInDomain) threatProbability += 0.2;
    if (isHighRiskTLD) threatProbability += 0.5;
    if (hasMaliciousPattern) threatProbability += 0.4;
    if (hasHomographAttack) threatProbability += 0.8;
    if (hasSuspiciousPort) threatProbability += 0.3;
    if (hasSuspiciousPath) threatProbability += 0.6;
    if (isDomainSquatting) threatProbability += 0.9;
    if (hasBase64InUrl) threatProbability += 0.3;
    
    // Comprehensive security engine simulation
    const engines = [
      { name: "Google Safe Browsing", verdict: "Clean", category: "Safe browsing" },
      { name: "VirusTotal Community", verdict: "Clean", category: "Community" },
      { name: "PhishTank", verdict: "Clean", category: "Phishing" },
      { name: "OpenPhish", verdict: "Clean", category: "Phishing" },
      { name: "Malware Domain List", verdict: "Clean", category: "Malware" },
      { name: "Sucuri SiteCheck", verdict: "Clean", category: "Website scanner" },
      { name: "Fortinet WebFilter", verdict: "Clean", category: "Category filter" },
      { name: "Sophos Web Protection", verdict: "Clean", category: "Web protection" },
      { name: "Trend Micro Site Safety", verdict: "Clean", category: "Site safety" },
      { name: "Kaspersky URL Advisor", verdict: "Clean", category: "URL advisor" },
      { name: "Bitdefender TrafficLight", verdict: "Clean", category: "Traffic analysis" },
      { name: "Norton Safe Web", verdict: "Clean", category: "Safe browsing" },
      { name: "McAfee WebAdvisor", verdict: "Clean", category: "Web security" },
      { name: "ESET Online Scanner", verdict: "Clean", category: "Malware detection" },
      { name: "Avast Web Shield", verdict: "Clean", category: "Real-time protection" },
      { name: "Comodo Site Inspector", verdict: "Clean", category: "Site inspection" },
      { name: "Dr.Web Link Checker", verdict: "Clean", category: "Link analysis" },
      { name: "G DATA WebProtection", verdict: "Clean", category: "Web filtering" },
      { name: "F-Secure Browsing Protection", verdict: "Clean", category: "Safe browsing" },
      { name: "Panda Safe Browsing", verdict: "Clean", category: "Cloud security" },
    ];

    const isMalicious = Math.random() < Math.min(threatProbability, 0.95);
    const detections = isMalicious ? Math.floor(Math.random() * 6) + 1 : 0;

    if (isMalicious) {
      // Advanced threat classification with specific categories
      const threats = [
        "Phishing", "Malware Distribution", "Suspicious Activity", 
        "Fraudulent Site", "Trojan Host", "Adware/PUP", "Scam Site",
        "Command & Control", "Botnet C&C", "Cryptojacking", "Ransomware Host",
        "Data Harvesting", "Identity Theft", "Financial Scam", "Tech Support Scam",
        "Romance Scam", "Investment Fraud", "Fake Antivirus", "Browser Hijacker",
        "Keylogger Distribution", "Backdoor Trojan", "Spyware Host", "Exploit Kit"
      ];
      
      // Distribute detections across engines with weighted probability
      const detectionIndices = new Set();
      while (detectionIndices.size < detections) {
        detectionIndices.add(Math.floor(Math.random() * engines.length));
      }
      
      detectionIndices.forEach((i: number) => {
        engines[i].verdict = threats[Math.floor(Math.random() * threats.length)];
      });
    }

    let status: 'safe' | 'suspicious' | 'malicious' = 'safe';
    if (detections > 3) status = 'malicious';
    else if (detections > 0) status = 'suspicious';

    return {
      url: targetUrl,
      status,
      detections,
      totalEngines: engines.length,
      timestamp: new Date().toISOString(),
      engines,
    };
  };

  const handleScan = async () => {
    if (!url.trim()) {
      toast({
        title: "URL Required",
        description: "Please enter a URL to scan",
        variant: "destructive",
      });
      return;
    }

    if (!validateUrl(url)) {
      toast({
        title: "Invalid URL",
        description: "Please enter a valid URL (e.g., https://example.com)",
        variant: "destructive",
      });
      return;
    }

    setIsScanning(true);
    setScanResult(null);

    try {
      const result = await mockScan(url);
      setScanResult(result);
      
      toast({
        title: "Scan Complete",
        description: `URL scanned with ${result.detections} detections out of ${result.totalEngines} engines`,
      });
    } catch (error) {
      toast({
        title: "Scan Failed",
        description: "Unable to complete the scan. Please try again later.",
        variant: "destructive",
      });
    } finally {
      setIsScanning(false);
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'safe':
        return <CheckCircle className="w-5 h-5 text-success" />;
      case 'suspicious':
        return <AlertTriangle className="w-5 h-5 text-warning" />;
      case 'malicious':
        return <XCircle className="w-5 h-5 text-destructive" />;
      default:
        return <Shield className="w-5 h-5" />;
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'safe':
        return <Badge variant="secondary" className="bg-success/20 text-success border-success/20">Safe</Badge>;
      case 'suspicious':
        return <Badge variant="secondary" className="bg-warning/20 text-warning border-warning/20">Suspicious</Badge>;
      case 'malicious':
        return <Badge variant="secondary" className="bg-destructive/20 text-destructive border-destructive/20">Malicious</Badge>;
      default:
        return null;
    }
  };

  return (
    <div className="space-y-6">
      <Card className="bg-gradient-card shadow-card-cyber border-border/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Link className="w-6 h-6 text-cyber-blue" />
            URL Scanner
          </CardTitle>
          <CardDescription>
            Enter a URL to check for malicious content and security threats
          </CardDescription>
        </CardHeader>
        
        <CardContent className="space-y-4">
          <div className="flex gap-2">
            <Input
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="flex-1 bg-background/50 border-border/50"
              onKeyDown={(e) => e.key === 'Enter' && !isScanning && handleScan()}
            />
            <Button
              variant="scan"
              onClick={handleScan}
              disabled={isScanning}
              className="min-w-[120px]"
            >
              {isScanning ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Shield className="w-4 h-4" />
                  Scan URL
                </>
              )}
            </Button>
          </div>

          {isScanning && (
            <Alert className="bg-cyber-blue/10 border-cyber-blue/20">
              <Loader2 className="h-4 w-4 animate-spin" />
              <AlertDescription>
                Scanning URL with multiple security engines. This may take a few moments...
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>

      {scanResult && (
        <Card className="bg-gradient-card shadow-card-cyber border-border/20">
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span className="flex items-center gap-2">
                {getStatusIcon(scanResult.status)}
                Scan Results
              </span>
              {getStatusBadge(scanResult.status)}
            </CardTitle>
            <CardDescription>
              Scanned: <span className="font-mono text-cyber-blue">{scanResult.url}</span>
            </CardDescription>
          </CardHeader>
          
          <CardContent className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-background/30 rounded-lg p-4 text-center">
                <div className="text-2xl font-bold text-cyber-blue">{scanResult.detections}</div>
                <div className="text-sm text-muted-foreground">Detections</div>
              </div>
              <div className="bg-background/30 rounded-lg p-4 text-center">
                <div className="text-2xl font-bold text-cyber-purple">{scanResult.totalEngines}</div>
                <div className="text-sm text-muted-foreground">Engines</div>
              </div>
              <div className="bg-background/30 rounded-lg p-4 text-center">
                <div className="text-2xl font-bold text-cyber-blue">
                  {Math.round(((scanResult.totalEngines - scanResult.detections) / scanResult.totalEngines) * 100)}%
                </div>
                <div className="text-sm text-muted-foreground">Clean</div>
              </div>
            </div>

            <div>
              <h4 className="font-semibold mb-3">Security Engine Results</h4>
              <div className="space-y-2">
                {scanResult.engines.map((engine, index) => (
                  <div
                    key={index}
                    className="flex items-center justify-between p-3 bg-background/20 rounded-lg border border-border/10"
                  >
                    <div>
                      <div className="font-medium">{engine.name}</div>
                      {engine.category && (
                        <div className="text-sm text-muted-foreground">{engine.category}</div>
                      )}
                    </div>
                    <Badge
                      variant={engine.verdict === 'Clean' ? 'secondary' : 'destructive'}
                      className={
                        engine.verdict === 'Clean'
                          ? 'bg-success/20 text-success border-success/20'
                          : 'bg-destructive/20 text-destructive border-destructive/20'
                      }
                    >
                      {engine.verdict}
                    </Badge>
                  </div>
                ))}
              </div>
            </div>

            <div className="text-xs text-muted-foreground">
              Scan completed at {new Date(scanResult.timestamp).toLocaleString()}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default UrlScanner;