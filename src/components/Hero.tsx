import { Button } from "@/components/ui/button";
import { Shield, Search, Upload } from "lucide-react";
import vulnsecLogo from "@/assets/vulnsec-logo.png";

const Hero = () => {
  return (
    <section className="relative min-h-screen bg-gradient-hero flex items-center justify-center overflow-hidden">
      {/* Animated background grid */}
      <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDAiIGhlaWdodD0iNDAiIHZpZXdCb3g9IjAgMCA0MCA0MCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPGcgaWQ9ImdyaWQiIG9wYWNpdHk9IjAuMSI+CjxwYXRoIGQ9Ik0wIDEwSDE0MEwxNDB2MjBIMCIgZmlsbD0iIzAwRkZGRiIvPgo8L2c+Cjwvc3ZnPgo=')] opacity-20"></div>
      
      <div className="container mx-auto px-4 text-center relative z-10">
        {/* Logo */}
        <div className="mb-8 flex justify-center">
          <img
            src="/lovable-uploads/ea65120f-2ee6-4717-aae1-57eb52db6788.png"
            alt="VulnSec Logo"
            className="w-32 h-32 md:w-40 md:h-40 drop-shadow-2xl animate-pulse"
          />
        </div>

        {/* Main heading */}
        <div className="mb-6">
          <h1 className="text-5xl md:text-7xl font-bold bg-gradient-cyber bg-clip-text text-transparent mb-4">
            VulnSec
          </h1>
          <p className="text-xl md:text-2xl text-muted-foreground max-w-3xl mx-auto leading-relaxed">
            Advanced Cybersecurity Scanner
          </p>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto mt-4">
            Scan URLs and files for malicious content with enterprise-grade security intelligence
          </p>
        </div>

        {/* Feature highlights */}
        <div className="grid md:grid-cols-3 gap-8 mb-12 max-w-4xl mx-auto">
          <div className="bg-gradient-card rounded-xl p-6 shadow-card-cyber border border-border/20">
            <Shield className="w-12 h-12 text-cyber-blue mx-auto mb-4" />
            <h3 className="text-xl font-semibold mb-2">URL Protection</h3>
            <p className="text-muted-foreground">Real-time scanning with Google Safe Browsing</p>
          </div>
          
          <div className="bg-gradient-card rounded-xl p-6 shadow-card-cyber border border-border/20">
            <Search className="w-12 h-12 text-cyber-purple mx-auto mb-4" />
            <h3 className="text-xl font-semibold mb-2">Threat Analysis</h3>
            <p className="text-muted-foreground">Multi-engine detection powered by VirusTotal</p>
          </div>
          
          <div className="bg-gradient-card rounded-xl p-6 shadow-card-cyber border border-border/20">
            <Upload className="w-12 h-12 text-cyber-blue mx-auto mb-4" />
            <h3 className="text-xl font-semibold mb-2">File Scanning</h3>
            <p className="text-muted-foreground">Deep inspection of suspicious files</p>
          </div>
        </div>

        {/* CTA buttons */}
        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <Button 
            variant="cyber" 
            size="xl"
            className="min-w-[200px]"
            onClick={() => document.getElementById('scanner')?.scrollIntoView({ behavior: 'smooth' })}
          >
            Start Scanning
          </Button>
          <Button 
            variant="outline" 
            size="xl"
            className="min-w-[200px] border-cyber-blue/50 text-cyber-blue hover:bg-cyber-blue/10"
            onClick={() => document.getElementById('security-tips')?.scrollIntoView({ behavior: 'smooth' })}
          >
            Security Tips
          </Button>
        </div>
      </div>
    </section>
  );
};

export default Hero;