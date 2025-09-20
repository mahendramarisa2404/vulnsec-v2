import { Loader2 } from "lucide-react";

interface LoadingSpinnerProps {
  message?: string;
  size?: "sm" | "md" | "lg";
}

const LoadingSpinner = ({ message = "Loading...", size = "md" }: LoadingSpinnerProps) => {
  const sizeClasses = {
    sm: "w-4 h-4",
    md: "w-6 h-6", 
    lg: "w-8 h-8"
  };

  return (
    <div className="flex items-center justify-center gap-2 p-4">
      <Loader2 className={`${sizeClasses[size]} animate-spin text-cyber-blue`} />
      <span className="text-sm text-muted-foreground">{message}</span>
    </div>
  );
};

export default LoadingSpinner;