import { useState } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import Hero from "@/components/Hero";
import SecurityWarning from "@/components/SecurityWarning";
import UrlScanner from "@/components/UrlScanner";
import FileScanner from "@/components/FileScanner";
import SecurityTips from "@/components/SecurityTips";
import ErrorBoundary from "@/components/ErrorBoundary";
import { Link, Upload } from "lucide-react";

const Index = () => {
  const [isAcknowledged, setIsAcknowledged] = useState(false);

  return (
    <div className="min-h-screen bg-gradient-hero">
      {/* Hero Section */}
      <Hero />
      
      {/* Scanner Section */}
      <section id="scanner" className="py-16">
        <div className="container mx-auto px-4">
          <div className="max-w-4xl mx-auto">
            <div className="text-center mb-12">
              <h2 className="text-4xl font-bold bg-gradient-cyber bg-clip-text text-transparent mb-4">
                Security Scanner
              </h2>
              <p className="text-xl text-muted-foreground">
                Analyze URLs and files for potential security threats
              </p>
            </div>

            {/* Security Warning */}
            {!isAcknowledged && (
              <div className="mb-8">
                <SecurityWarning 
                  onAcknowledge={setIsAcknowledged}
                  isAcknowledged={isAcknowledged}
                />
              </div>
            )}

            {/* Scanner Interface */}
            {isAcknowledged && (
              <Tabs defaultValue="url" className="w-full">
                <TabsList className="grid w-full grid-cols-2 mb-8 bg-background/20 border border-border/20">
                  <TabsTrigger 
                    value="url" 
                    className="data-[state=active]:bg-cyber-blue/20 data-[state=active]:text-cyber-blue"
                  >
                    <Link className="w-4 h-4 mr-2" />
                    URL Scanner
                  </TabsTrigger>
                  <TabsTrigger 
                    value="file"
                    className="data-[state=active]:bg-cyber-purple/20 data-[state=active]:text-cyber-purple"
                  >
                    <Upload className="w-4 h-4 mr-2" />
                    File Scanner
                  </TabsTrigger>
                </TabsList>
                
                <TabsContent value="url" className="space-y-6">
                  <ErrorBoundary>
                    <UrlScanner />
                  </ErrorBoundary>
                </TabsContent>
                
                <TabsContent value="file" className="space-y-6">
                  <ErrorBoundary>
                    <FileScanner />
                  </ErrorBoundary>
                </TabsContent>
              </Tabs>
            )}
          </div>
        </div>
      </section>

      {/* Security Tips Section */}
      <SecurityTips />

      {/* Footer */}
      <footer className="py-12 border-t border-border/20">
        <div className="container mx-auto px-4 text-center">
          <div className="mb-6">
            <h3 className="text-2xl font-bold bg-gradient-cyber bg-clip-text text-transparent mb-2">
              VulnSec
            </h3>
            <p className="text-muted-foreground">
              Advanced Cybersecurity Scanner - Protecting you from digital threats
            </p>
          </div>
          
          <div className="text-sm text-muted-foreground space-y-2">
            <p>
              VulnSec integrates with industry-leading security services including Google Safe Browsing and VirusTotal
            </p>
            <p>
              Always exercise caution when dealing with suspicious content. When in doubt, don't click or download.
            </p>
            <p className="mt-4 pt-4 border-t border-border/20">
              © 2024 VulnSec. Built for educational and security research purposes.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Index;