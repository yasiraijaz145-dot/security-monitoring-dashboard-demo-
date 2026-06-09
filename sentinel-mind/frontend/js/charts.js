function drawTimeline(events) {
  const canvas = document.getElementById('timelineCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.parentElement.clientWidth - 32;
  const H = 200;
  canvas.width = W; canvas.height = H;
  ctx.clearRect(0, 0, W, H);

  // Background grid
  ctx.strokeStyle = 'rgba(28,35,51,1)';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = (H - 40) * i / 4 + 10;
    ctx.beginPath(); ctx.moveTo(40, y); ctx.lineTo(W - 10, y); ctx.stroke();
  }

  if (!events.length) return;
  const recent = events.slice(0, 30).reverse();
  const barW = Math.max(4, (W - 60) / 30 - 2);
  const colors = { CRITICAL:'#f85149', HIGH:'#d29922', MEDIUM:'#58a6ff', LOW:'#3fb950' };

  recent.forEach((ev, i) => {
    const x = 42 + i * ((W - 60) / 30);
    const h = Math.max(4, (ev.risk_score / 100) * (H - 50));
    const y = H - 30 - h;
    ctx.fillStyle = colors[ev.risk_level] || '#484f58';
    ctx.beginPath();
    ctx.roundRect(x, y, barW, h, 2);
    ctx.fill();
  });

  // Y axis label
  ctx.fillStyle = '#484f58';
  ctx.font = '9px JetBrains Mono, monospace';
  ctx.textAlign = 'right';
  ctx.fillText('Risk', 35, 14);
  ctx.fillText('100', 35, 20);
  ctx.fillText('0', 35, H - 28);
  ctx.textAlign = 'center';
  ctx.fillText('← Last 30 events', W / 2, H - 8);
}