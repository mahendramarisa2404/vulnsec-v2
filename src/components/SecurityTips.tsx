import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { 
  Shield, 
  Eye, 
  Wifi, 
  Download, 
  Mail, 
  Lock, 
  Smartphone, 
  Globe,
  AlertTriangle,
  CheckCircle
} from "lucide-react";

const SecurityTips = () => {
  const tips = [
    {
      icon: <Eye className="w-8 h-8 text-cyber-blue" />,
      title: "Check Before You Click",
      description: "Always hover over links to see the full URL before clicking. Be suspicious of shortened URLs or links that don't match the expected destination.",
      priority: "high"
    },
    {
      icon: <Mail className="w-8 h-8 text-cyber-purple" />,
      title: "Beware of Phishing",
      description: "Be cautious of emails or messages asking for personal information. Legitimate companies will never ask for passwords or sensitive data via email.",
      priority: "high"
    },
    {
      icon: <Download className="w-8 h-8 text-cyber-blue" />,
      title: "Safe Downloading",
      description: "Only download software from official websites and app stores. Scan all downloads with antivirus before opening.",
      priority: "high"
    },
    {
      icon: <Wifi className="w-8 h-8 text-cyber-purple" />,
      title: "Use a VPN",
      description: "Use a Virtual Private Network (VPN) on public Wi-Fi networks to encrypt your traffic and protect your privacy.",
      priority: "medium"
    },
    {
      icon: <Lock className="w-8 h-8 text-cyber-blue" />,
      title: "Strong Passwords",
      description: "Use unique, complex passwords for each account. Consider using a password manager to generate and store secure passwords.",
      priority: "high"
    },
    {
      icon: <Smartphone className="w-8 h-8 text-cyber-purple" />,
      title: "Keep Software Updated",
      description: "Regularly update your operating system, browsers, and applications to patch security vulnerabilities.",
      priority: "medium"
    },
    {
      icon: <Globe className="w-8 h-8 text-cyber-blue" />,
      title: "Verify Website Security",
      description: "Look for HTTPS (the lock icon) in your browser's address bar before entering sensitive information.",
      priority: "medium"
    },
    {
      icon: <Shield className="w-8 h-8 text-cyber-purple" />,
      title: "Enable Two-Factor Authentication",
      description: "Add an extra layer of security to your accounts by enabling 2FA whenever possible.",
      priority: "high"
    }
  ];

  const getPriorityBadge = (priority: string) => {
    switch (priority) {
      case 'high':
        return <Badge className="bg-destructive/20 text-destructive border-destructive/20">Critical</Badge>;
      case 'medium':
        return <Badge className="bg-warning/20 text-warning border-warning/20">Important</Badge>;
      default:
        return <Badge className="bg-cyber-blue/20 text-cyber-blue border-cyber-blue/20">Recommended</Badge>;
    }
  };

  const getPriorityIcon = (priority: string) => {
    switch (priority) {
      case 'high':
        return <AlertTriangle className="w-4 h-4 text-destructive" />;
      case 'medium':
        return <AlertTriangle className="w-4 h-4 text-warning" />;
      default:
        return <CheckCircle className="w-4 h-4 text-cyber-blue" />;
    }
  };

  return (
    <section id="security-tips" className="py-16 bg-gradient-hero">
      <div className="container mx-auto px-4">
        <div className="text-center mb-12">
          <h2 className="text-4xl font-bold bg-gradient-cyber bg-clip-text text-transparent mb-4">
            Security Best Practices
          </h2>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            Follow these essential cybersecurity tips to protect yourself and your data from online threats
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-2 gap-6 max-w-6xl mx-auto">
          {tips.map((tip, index) => (
            <Card key={index} className="bg-gradient-card shadow-card-cyber border-border/20 hover:shadow-glow transition-all duration-300">
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    {tip.icon}
                    <span className="text-xl">{tip.title}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {getPriorityIcon(tip.priority)}
                    {getPriorityBadge(tip.priority)}
                  </div>
                </CardTitle>
              </CardHeader>
              
              <CardContent>
                <p className="text-muted-foreground leading-relaxed">
                  {tip.description}
                </p>
              </CardContent>
            </Card>
          ))}
        </div>

        <div className="mt-16">
          <Card className="bg-gradient-card shadow-card-cyber border-cyber-blue/20 max-w-4xl mx-auto">
            <CardHeader className="text-center">
              <CardTitle className="flex items-center justify-center gap-2 text-2xl">
                <Shield className="w-8 h-8 text-cyber-blue" />
                Remember: Prevention is Key
              </CardTitle>
              <CardDescription className="text-lg">
                The best defense against cyber threats is staying informed and vigilant
              </CardDescription>
            </CardHeader>
            
            <CardContent className="space-y-4">
              <div className="grid md:grid-cols-2 gap-6 text-center">
                <div className="bg-background/30 rounded-lg p-6">
                  <div className="text-3xl font-bold text-cyber-blue mb-2">90%</div>
                  <div className="text-sm text-muted-foreground">of cyber attacks can be prevented with basic security practices</div>
                </div>
                <div className="bg-background/30 rounded-lg p-6">
                  <div className="text-3xl font-bold text-cyber-purple mb-2">24/7</div>
                  <div className="text-sm text-muted-foreground">Stay vigilant - threats can emerge at any time</div>
                </div>
              </div>
              
              <div className="text-center bg-cyber-blue/10 rounded-lg p-4 border border-cyber-blue/20">
                <p className="text-foreground font-medium">
                  🛡️ <strong>Pro Tip:</strong> Regularly scan suspicious URLs and files using tools like VulnSec to identify potential threats before they can harm your system.
                </p>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </section>
  );
};

export default SecurityTips;