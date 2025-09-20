import React, { useState, useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Loader2, Link, Shield, AlertTriangle, CheckCircle, XCircle } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";
import { urlScanCache } from "@/utils/cache";
import { useRetry } from "@/hooks/useRetry";

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
  const { retry, isRetrying, attempt } = useRetry({ maxAttempts: 3, delayMs: 2000 });

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

  const scanUrl = async (targetUrl: string): Promise<ScanResult> => {
    // Check cache first
    const cacheKey = `url:${targetUrl}`;
    const cached = urlScanCache.get(cacheKey) as ScanResult | null;
    if (cached) {
      toast({
        title: "Using Cached Result",
        description: "Recent scan result found in cache",
      });
      return cached;
    }

    try {
      const response = await supabase.functions.invoke('scan-url', {
        body: { url: targetUrl }
      });

      if (response.error) {
        throw new Error(response.error.message || 'Failed to scan URL');
      }

      // Cache the result for 10 minutes
      urlScanCache.set(cacheKey, response.data, 10);
      return response.data;
    } catch (error) {
      console.error('URL scan error:', error);
      throw error;
    }
  };

  const handleScan = useCallback(async () => {
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
      const result = await retry(() => scanUrl(url));
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
  }, [url, retry]);

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
                  {isRetrying ? `Retrying... (${attempt}/3)` : 'Scanning...'}
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

export default React.memo(UrlScanner);