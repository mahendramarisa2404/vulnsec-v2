import { useState, useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Loader2, Upload, FileText, AlertTriangle, CheckCircle, XCircle, Download } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface FileResult {
  filename: string;
  size: number;
  hash: string;
  status: 'safe' | 'suspicious' | 'malicious';
  detections: number;
  totalEngines: number;
  timestamp: string;
  engines: Array<{
    name: string;
    verdict: string;
    version?: string;
  }>;
}

const FileScanner = () => {
  const [isDragOver, setIsDragOver] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<FileResult | null>(null);
  const { toast } = useToast();

  const allowedTypes = [
    'application/pdf',
    'image/jpeg',
    'image/jpg', 
    'image/png',
    'image/gif',
    'image/bmp',
    'image/webp',
    'application/zip',
    'application/x-zip-compressed',
    'application/x-rar-compressed',
    'application/x-7z-compressed',
    'text/plain',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation'
  ];

  const dangerousExtensions = [
    '.exe', '.bat', '.cmd', '.scr', '.pif', '.com', '.vbs', '.js', '.jar', '.msi', 
    '.dll', '.sys', '.drv', '.bin', '.deb', '.rpm', '.dmg', '.pkg', '.app'
  ];

  const maxFileSize = 32 * 1024 * 1024; // 32MB
  const minFileSize = 1; // 1 byte minimum

  const validateFile = (file: File): boolean => {
    // Check file size limits
    if (file.size > maxFileSize) {
      toast({
        title: "File Too Large",
        description: "File size must be less than 32MB",
        variant: "destructive",
      });
      return false;
    }

    if (file.size < minFileSize) {
      toast({
        title: "Invalid File",
        description: "File appears to be empty or corrupted",
        variant: "destructive",
      });
      return false;
    }

    // Check for dangerous file extensions
    const fileName = file.name.toLowerCase();
    const isDangerous = dangerousExtensions.some(ext => fileName.endsWith(ext));
    
    if (isDangerous) {
      toast({
        title: "Dangerous File Type",
        description: "Executable files and scripts are not allowed for security reasons",
        variant: "destructive",
      });
      return false;
    }

    // Strict MIME type validation
    if (!allowedTypes.includes(file.type)) {
      toast({
        title: "File Type Not Supported",
        description: "Only PDF, images, archives, and office documents are allowed",
        variant: "destructive",
      });
      return false;
    }

    // Additional filename validation
    if (fileName.includes('..') || fileName.includes('/') || fileName.includes('\\')) {
      toast({
        title: "Invalid File Name",
        description: "File name contains invalid characters",
        variant: "destructive",
      });
      return false;
    }

    return true;
  };

  const mockFileScan = async (file: File): Promise<FileResult> => {
    // Simulate API delay
    await new Promise(resolve => setTimeout(resolve, 4000));
    
    // Mock hash generation
    const hash = `sha256:${Math.random().toString(36).substring(2, 15)}${Math.random().toString(36).substring(2, 15)}`;
    
    // Mock antivirus engines
    const engines = [
      { name: "Microsoft Defender", verdict: "Clean", version: "1.381.2149.0" },
      { name: "Kaspersky", verdict: "Clean", version: "21.0.13.481" },
      { name: "Norton", verdict: "Clean", version: "22.20.5.39" },
      { name: "Bitdefender", verdict: "Clean", version: "7.90796" },
      { name: "Avast", verdict: "Clean", version: "21.1.2449.0" },
      { name: "McAfee", verdict: "Clean", version: "6.0.6.653" },
      { name: "Trend Micro", verdict: "Clean", version: "14.0.0.4071" },
      { name: "ESET-NOD32", verdict: "Clean", version: "24279" },
      { name: "F-Secure", verdict: "Clean", version: "18.10.1137.128" },
      { name: "Sophos", verdict: "Clean", version: "1.4.1.0" },
    ];

    // Enhanced threat detection based on file characteristics
    const fileName = file.name.toLowerCase();
    const suspiciousPatterns = [
      'invoice', 'receipt', 'document', 'urgent', 'confidential', 'secure',
      'crypto', 'wallet', 'bitcoin', 'payment', 'bank', 'tax'
    ];
    
    const isSuspiciousName = suspiciousPatterns.some(pattern => fileName.includes(pattern));
    const isLargeFile = file.size > 10 * 1024 * 1024; // 10MB+
    const isUncommonType = !['application/pdf', 'image/jpeg', 'image/png'].includes(file.type);
    
    // Calculate threat probability based on multiple factors
    let threatProbability = 0.02; // Base 2% chance
    if (isSuspiciousName) threatProbability += 0.15;
    if (isLargeFile) threatProbability += 0.05;
    if (isUncommonType) threatProbability += 0.08;
    
    const isMalicious = Math.random() < threatProbability;
    const detections = isMalicious ? Math.floor(Math.random() * 5) + 1 : 0;

    if (isMalicious) {
      // Mark engines as detecting specific threats
      const threats = [
        "Trojan.Generic.KD", "Win32.Malware-gen", "PUA.Win32.Packed", 
        "Adware.Generic.BHO", "Trojan.Script.Generic", "Backdoor.Generic",
        "Spyware.KeyLogger", "Ransomware.Generic"
      ];
      for (let i = 0; i < detections; i++) {
        engines[i].verdict = threats[Math.floor(Math.random() * threats.length)];
      }
    }

    let status: 'safe' | 'suspicious' | 'malicious' = 'safe';
    if (detections > 2) status = 'malicious';
    else if (detections > 0) status = 'suspicious';

    return {
      filename: file.name,
      size: file.size,
      hash,
      status,
      detections,
      totalEngines: engines.length,
      timestamp: new Date().toISOString(),
      engines,
    };
  };

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    
    const files = Array.from(e.dataTransfer.files);
    if (files.length > 0) {
      const file = files[0];
      if (validateFile(file)) {
        setSelectedFile(file);
      }
    }
  }, []);

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      const file = files[0];
      if (validateFile(file)) {
        setSelectedFile(file);
      }
    }
  };

  const handleScan = async () => {
    if (!selectedFile) return;

    setIsScanning(true);
    setScanResult(null);

    try {
      const result = await mockFileScan(selectedFile);
      setScanResult(result);
      
      toast({
        title: "File Scan Complete",
        description: `${result.filename} scanned with ${result.detections} detections out of ${result.totalEngines} engines`,
      });
    } catch (error) {
      toast({
        title: "Scan Failed",
        description: "Unable to complete the file scan. Please try again later.",
        variant: "destructive",
      });
    } finally {
      setIsScanning(false);
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
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
        return <FileText className="w-5 h-5" />;
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'safe':
        return <Badge className="bg-success/20 text-success border-success/20">Safe</Badge>;
      case 'suspicious':
        return <Badge className="bg-warning/20 text-warning border-warning/20">Suspicious</Badge>;
      case 'malicious':
        return <Badge className="bg-destructive/20 text-destructive border-destructive/20">Malicious</Badge>;
      default:
        return null;
    }
  };

  return (
    <div className="space-y-6">
      <Card className="bg-gradient-card shadow-card-cyber border-border/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Upload className="w-6 h-6 text-cyber-purple" />
            File Scanner
          </CardTitle>
          <CardDescription>
            Upload files to scan for malware and security threats (Max 32MB)
          </CardDescription>
        </CardHeader>
        
        <CardContent className="space-y-4">
          <div
            className={`border-2 border-dashed rounded-lg p-8 text-center transition-all duration-300 ${
              isDragOver
                ? 'border-cyber-blue bg-cyber-blue/5'
                : 'border-border/50 hover:border-cyber-purple/50'
            }`}
            onDrop={handleDrop}
            onDragOver={(e) => {
              e.preventDefault();
              setIsDragOver(true);
            }}
            onDragLeave={() => setIsDragOver(false)}
          >
            <Upload className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
            <div className="space-y-2">
              <p className="font-medium">
                {selectedFile ? selectedFile.name : 'Drop files here or click to browse'}
              </p>
              <p className="text-sm text-muted-foreground">
                Supports PDF, images, ZIP, and document files
              </p>
              {selectedFile && (
                <p className="text-sm text-cyber-blue">
                  Size: {formatFileSize(selectedFile.size)}
                </p>
              )}
            </div>
            <input
              type="file"
              onChange={handleFileSelect}
              className="hidden"
              id="file-upload"
              accept=".pdf,.jpg,.jpeg,.png,.gif,.zip,.txt,.xls,.xlsx"
            />
            <label htmlFor="file-upload">
              <Button variant="outline" className="mt-4" asChild>
                <span className="cursor-pointer">Browse Files</span>
              </Button>
            </label>
          </div>

          {selectedFile && (
            <div className="flex justify-center">
              <Button
                variant="scan"
                onClick={handleScan}
                disabled={isScanning}
                className="min-w-[160px]"
              >
                {isScanning ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Scanning File...
                  </>
                ) : (
                  <>
                    <FileText className="w-4 h-4" />
                    Scan File
                  </>
                )}
              </Button>
            </div>
          )}

          {isScanning && (
            <Alert className="bg-cyber-purple/10 border-cyber-purple/20">
              <Loader2 className="h-4 w-4 animate-spin" />
              <AlertDescription>
                Analyzing file with multiple antivirus engines. Please wait...
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
                File Scan Results
              </span>
              {getStatusBadge(scanResult.status)}
            </CardTitle>
            <CardDescription>
              File: <span className="font-mono text-cyber-purple">{scanResult.filename}</span>
            </CardDescription>
          </CardHeader>
          
          <CardContent className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-background/30 rounded-lg p-4 text-center">
                <div className="text-2xl font-bold text-cyber-purple">{scanResult.detections}</div>
                <div className="text-sm text-muted-foreground">Detections</div>
              </div>
              <div className="bg-background/30 rounded-lg p-4 text-center">
                <div className="text-2xl font-bold text-cyber-blue">{scanResult.totalEngines}</div>
                <div className="text-sm text-muted-foreground">Engines</div>
              </div>
              <div className="bg-background/30 rounded-lg p-4 text-center">
                <div className="text-2xl font-bold text-success">
                  {Math.round(((scanResult.totalEngines - scanResult.detections) / scanResult.totalEngines) * 100)}%
                </div>
                <div className="text-sm text-muted-foreground">Clean</div>
              </div>
              <div className="bg-background/30 rounded-lg p-4 text-center">
                <div className="text-lg font-bold text-cyber-blue">{formatFileSize(scanResult.size)}</div>
                <div className="text-sm text-muted-foreground">File Size</div>
              </div>
            </div>

            <div className="bg-background/20 rounded-lg p-4">
              <h4 className="font-semibold mb-2">File Information</h4>
              <div className="text-sm text-muted-foreground space-y-1">
                <div><strong>SHA-256:</strong> <span className="font-mono">{scanResult.hash}</span></div>
                <div><strong>Scan Date:</strong> {new Date(scanResult.timestamp).toLocaleString()}</div>
              </div>
            </div>

            <div>
              <h4 className="font-semibold mb-3">Antivirus Engine Results</h4>
              <div className="space-y-2 max-h-64 overflow-y-auto">
                {scanResult.engines.map((engine, index) => (
                  <div
                    key={index}
                    className="flex items-center justify-between p-3 bg-background/20 rounded-lg border border-border/10"
                  >
                    <div>
                      <div className="font-medium">{engine.name}</div>
                      {engine.version && (
                        <div className="text-sm text-muted-foreground">v{engine.version}</div>
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

            <div className="flex justify-center">
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  const data = JSON.stringify(scanResult, null, 2);
                  const blob = new Blob([data], { type: 'application/json' });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement('a');
                  a.href = url;
                  a.download = `${scanResult.filename}_scan_report.json`;
                  a.click();
                  URL.revokeObjectURL(url);
                }}
                className="border-cyber-blue/50 text-cyber-blue hover:bg-cyber-blue/10"
              >
                <Download className="w-4 h-4 mr-2" />
                Download Report
              </Button>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default FileScanner;