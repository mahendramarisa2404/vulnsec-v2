import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { corsHeaders } from '../_shared/cors.ts'

interface VirusTotalFileResponse {
  data: {
    id: string;
    attributes: {
      stats: {
        harmless: number;
        malicious: number;
        suspicious: number;
        undetected: number;
      };
      results: Record<string, {
        category: string;
        engine_name: string;
        result: string;
        version: string;
      }>;
    };
  };
}

serve(async (req) => {
  // Handle CORS preflight requests
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders })
  }

  try {
    const formData = await req.formData()
    const file = formData.get('file') as File
    
    if (!file) {
      return new Response(
        JSON.stringify({ error: 'File is required' }),
        { 
          status: 400, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        }
      )
    }

    const apiKey = Deno.env.get('VIRUSTOTAL_API_KEY')
    if (!apiKey) {
      return new Response(
        JSON.stringify({ error: 'API key not configured' }),
        { 
          status: 500, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        }
      )
    }

    // Check file size limit (32MB for VirusTotal)
    if (file.size > 32 * 1024 * 1024) {
      return new Response(
        JSON.stringify({ error: 'File too large. Maximum size is 32MB.' }),
        { 
          status: 413, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        }
      )
    }

    // Submit file for scanning
    const submitFormData = new FormData()
    submitFormData.append('file', file)

    const submitResponse = await fetch('https://www.virustotal.com/api/v3/files', {
      method: 'POST',
      headers: {
        'x-apikey': apiKey,
      },
      body: submitFormData,
    })

    if (!submitResponse.ok) {
      throw new Error(`VirusTotal submission failed: ${submitResponse.status}`)
    }

    const submitData = await submitResponse.json()
    const analysisId = submitData.data.id

    // Wait for analysis to begin
    await new Promise(resolve => setTimeout(resolve, 5000))

    // Get analysis results with retry logic
    let attempts = 0
    const maxAttempts = 15
    let analysisData: VirusTotalFileResponse

    while (attempts < maxAttempts) {
      const analysisResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        headers: {
          'x-apikey': apiKey,
        },
      })

      if (!analysisResponse.ok) {
        throw new Error(`VirusTotal analysis failed: ${analysisResponse.status}`)
      }

      analysisData = await analysisResponse.json()

      // Check if analysis is complete
      if (analysisData.data.attributes.stats) {
        break
      }

      attempts++
      await new Promise(resolve => setTimeout(resolve, 4000))
    }

    if (!analysisData!.data.attributes.stats) {
      return new Response(
        JSON.stringify({ error: 'Analysis timeout - please try again later' }),
        { 
          status: 408, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        }
      )
    }

    const stats = analysisData!.data.attributes.stats
    const results = analysisData!.data.attributes.results
    
    // Transform results to match our interface
    const engines = Object.entries(results).map(([engineName, result]) => ({
      name: result.engine_name || engineName,
      verdict: result.result === 'null' ? 'Clean' : (result.result || 'Unknown'),
      category: result.category || 'Antivirus',
      version: result.version,
    }))

    const detections = stats.malicious + stats.suspicious
    const totalEngines = stats.harmless + stats.malicious + stats.suspicious + stats.undetected

    let status: 'safe' | 'suspicious' | 'malicious' = 'safe'
    if (stats.malicious > 0) status = 'malicious'
    else if (stats.suspicious > 0) status = 'suspicious'

    // Calculate file risk score based on multiple factors
    const riskFactors = {
      hasHighDetectionRate: detections > totalEngines * 0.1,
      isSuspiciousExtension: /\.(exe|scr|bat|cmd|pif|com|vbs|js|jar|dmg|app)$/i.test(file.name),
      isLargeFile: file.size > 10 * 1024 * 1024,
      hasObfuscatedName: /[^\x20-\x7E]/.test(file.name),
    }

    const riskScore = Object.values(riskFactors).filter(Boolean).length

    const scanResult = {
      fileName: file.name,
      fileSize: file.size,
      fileType: file.type || 'unknown',
      status,
      detections,
      totalEngines,
      riskScore,
      timestamp: new Date().toISOString(),
      engines,
      riskFactors,
    }

    return new Response(
      JSON.stringify(scanResult),
      { 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
      }
    )

  } catch (error) {
    console.error('File scan error:', error)
    return new Response(
      JSON.stringify({ 
        error: 'Internal server error',
        details: error.message 
      }),
      { 
        status: 500, 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
      }
    )
  }
})