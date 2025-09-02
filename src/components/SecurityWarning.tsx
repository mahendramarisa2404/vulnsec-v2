import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { AlertTriangle, Shield } from "lucide-react";

interface SecurityWarningProps {
  onAcknowledge: (acknowledged: boolean) => void;
  isAcknowledged: boolean;
}

const SecurityWarning = ({ onAcknowledge, isAcknowledged }: SecurityWarningProps) => {
  const [showWarning, setShowWarning] = useState(!isAcknowledged);

  if (!showWarning && isAcknowledged) return null;

  return (
    <Card className="bg-gradient-card border-warning/20 shadow-card-cyber">
      <CardHeader className="text-center">
        <div className="flex justify-center mb-4">
          <AlertTriangle className="w-16 h-16 text-warning animate-pulse" />
        </div>
        <CardTitle className="text-2xl text-warning flex items-center justify-center gap-2">
          <Shield className="w-6 h-6" />
          IMPORTANT SAFETY WARNING
        </CardTitle>
        <CardDescription className="text-lg text-muted-foreground">
          Please read carefully before proceeding
        </CardDescription>
      </CardHeader>
      
      <CardContent className="space-y-6">
        <div className="bg-warning/10 rounded-lg p-6 border border-warning/20">
          <p className="text-foreground font-medium leading-relaxed">
            This tool is for <strong>security analysis only</strong>. Do NOT upload or scan any 
            personal, private, or sensitive files, documents, or URLs. The data you submit will be 
            shared with third-party security services and could become public.
          </p>
        </div>

        <div className="space-y-4">
          <h4 className="font-semibold text-lg">⚠️ Before you proceed:</h4>
          <ul className="space-y-2 text-muted-foreground">
            <li className="flex items-start gap-2">
              <span className="text-warning">•</span>
              <span>Only scan URLs and files you suspect may be malicious</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-warning">•</span>
              <span>Never upload confidential documents, personal photos, or sensitive data</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-warning">•</span>
              <span>All scanned content is shared with Google Safe Browsing and VirusTotal</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-warning">•</span>
              <span>Results may be stored and analyzed by security researchers</span>
            </li>
          </ul>
        </div>

        <div className="flex items-center space-x-3 p-4 bg-cyber-dark/30 rounded-lg border border-cyber-blue/20">
          <Checkbox
            id="acknowledge"
            checked={isAcknowledged}
            onCheckedChange={(checked) => {
              onAcknowledge(!!checked);
              if (checked) {
                setTimeout(() => setShowWarning(false), 500);
              }
            }}
            className="border-cyber-blue/50 data-[state=checked]:bg-cyber-blue"
          />
          <label
            htmlFor="acknowledge"
            className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70 cursor-pointer flex-1"
          >
            I understand and acknowledge this warning. I will only scan suspicious content and will not upload personal or sensitive data.
          </label>
        </div>

        {isAcknowledged && (
          <div className="text-center">
            <Button
              variant="success"
              onClick={() => setShowWarning(false)}
              className="min-w-[200px]"
            >
              Continue to Scanner
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default SecurityWarning;