import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { corsHeaders } from '../_shared/cors.ts'

interface VirusTotalUrlResponse {
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
        method: string;
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
    const { url } = await req.json()
    
    if (!url) {
      return new Response(
        JSON.stringify({ error: 'URL is required' }),
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

    // Submit URL for scanning
    const submitResponse = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: {
        'x-apikey': apiKey,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `url=${encodeURIComponent(url)}`,
    })

    if (!submitResponse.ok) {
      throw new Error(`VirusTotal submission failed: ${submitResponse.status}`)
    }

    const submitData = await submitResponse.json()
    const analysisId = submitData.data.id

    // Wait a moment for analysis to begin
    await new Promise(resolve => setTimeout(resolve, 2000))

    // Get analysis results with retry logic
    let attempts = 0
    const maxAttempts = 10
    let analysisData: VirusTotalUrlResponse

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
      await new Promise(resolve => setTimeout(resolve, 3000))
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
      verdict: result.result === 'clean' ? 'Clean' : (result.result || 'Unknown'),
      category: result.category || 'Security scan',
    }))

    const detections = stats.malicious + stats.suspicious
    const totalEngines = stats.harmless + stats.malicious + stats.suspicious + stats.undetected

    let status: 'safe' | 'suspicious' | 'malicious' = 'safe'
    if (stats.malicious > 0) status = 'malicious'
    else if (stats.suspicious > 0) status = 'suspicious'

    const scanResult = {
      url,
      status,
      detections,
      totalEngines,
      timestamp: new Date().toISOString(),
      engines,
    }

    return new Response(
      JSON.stringify(scanResult),
      { 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
      }
    )

  } catch (error) {
    console.error('URL scan error:', error)
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