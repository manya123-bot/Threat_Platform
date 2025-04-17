// … keep your fetchAbuseIPDB / fetchVirusTotal / fetchShodan funcs …

app.post('/fetch_data', async (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ error: 'IP address is required' });
  
    try {
      const [abuseData, virusTotalData, shodanData] = await Promise.all([
        fetchAbuseIPDB(ip),
        fetchVirusTotal(ip),
        fetchShodan(ip),
      ]);
  
      // Safely dig out the numeric fields (you may need to adjust these paths)
      const isPublic        = abuseData?.data?.isPublic           || 0;
      const confidenceScore = abuseData?.data?.abuseConfidenceScore || 0;
      const maliciousCount  = virusTotalData?.data?.attributes?.last_analysis_stats?.malicious || 0;
      const countryCode     = abuseData?.data?.countryCode       || shodanData?.country_code || null;
      const isp             = abuseData?.data?.isp               || shodanData?.org || null;
  
      // threatLevel logic
      const score = confidenceScore + maliciousCount * 5;
      let threatLevel = 'low';
      if (score > 50) threatLevel = 'critical';
      else if (score > 30) threatLevel = 'high';
      else if (score > 15) threatLevel = 'medium';
  
      // Now insert into columns
      const insertSQL = `
        INSERT INTO ThreatData 
          (ip, isPublic, confidenceScore, maliciousCount, countryCode, isp, threatLevel, rawData)
       VALUES (?, ?, ?, ?, ?, ?, ?, JSON.stringify({ abuseData, virusTotalData, shodanData }))
      `;
      const params = [
        ip,
        isPublic,
        confidenceScore,
        maliciousCount,
        countryCode,
        isp,
        threatLevel,
        JSON.stringify({ abuseData, virusTotalData, shodanData })
      ];
  
      connection.query(insertSQL, params, (err) => {
        if (err) {
          console.error('MySQL insert error:', err);
          return res.status(500).json({ error: 'Error saving data' });
        }
        // Respond with both raw and parsed for your front‑end
        res.json({ ip, isPublic, confidenceScore, maliciousCount, countryCode, isp, threatLevel });
      });
  
    } catch (err) {
      console.error('Fetch error:', err);
      res.status(500).json({ error: 'Error fetching threat intelligence data' });
    }
  });
  