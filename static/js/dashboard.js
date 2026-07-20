document.addEventListener('DOMContentLoaded', () => {
    const SEV_COLORS = {
        Critical: '#EF4444',
        High:     '#F97316',
        Medium:   '#EAB308',
        Low:      '#22C55E',
    };

    const CHART_DEFAULTS = {
        plugins: { legend: { labels: { color: '#CBD5E1', font: { size: 12 } } } },
        scales:  { x: { ticks: { color: '#64748B' }, grid: { color: 'rgba(255,255,255,0.05)' } },
                   y: { ticks: { color: '#64748B' }, grid: { color: 'rgba(255,255,255,0.05)' } } },
    };

    // ── Pie + Bar ──────────────────────────────────────────────
    fetch('/api/chart-data').then(r => r.json()).then(data => {

        // Pie — map colours by label so Critical is always red
        const pieLabels = Object.keys(data.severity);
        const pieValues = Object.values(data.severity);
        const pieColors = pieLabels.map(l => SEV_COLORS[l] || '#64748B');

        new Chart(document.getElementById('pieChart'), {
            type: 'doughnut',
            data: {
                labels: pieLabels,
                datasets: [{ data: pieValues, backgroundColor: pieColors, borderWidth: 2, borderColor: '#1E293B' }]
            },
            options: {
                plugins: {
                    legend: { position: 'right', labels: { color: '#CBD5E1', font: { size: 12 }, padding: 16 } }
                },
                cutout: '60%',
            }
        });

        // Bar
        new Chart(document.getElementById('barChart'), {
            type: 'bar',
            data: {
                labels: data.top_types.map(x => x.type),
                datasets: [{
                    label: 'Count',
                    data: data.top_types.map(x => x.count),
                    backgroundColor: 'rgba(59,130,246,0.7)',
                    borderColor: '#3B82F6',
                    borderWidth: 1,
                    borderRadius: 4,
                }]
            },
            options: {
                indexAxis: 'y',
                plugins: { legend: { display: false } },
                scales: {
                    x: { ticks: { color: '#64748B' }, grid: { color: 'rgba(255,255,255,0.05)' } },
                    y: { ticks: { color: '#CBD5E1', font: { size: 11 } }, grid: { display: false } },
                }
            }
        });
    });

    // ── Timeline + recent threats table ───────────────────────
    fetch('/api/threats?limit=50').then(r => r.json()).then(rows => {

        // Recent threats table with severity badges
        const tb = document.getElementById('recentThreats');
        tb.innerHTML = '';
        rows.slice(0, 20).forEach(r => {
            const badgeClass = { Critical:'badge-critical', High:'badge-high', Medium:'badge-medium', Low:'badge-low' }[r.severity] || 'badge-low';
            const tr = document.createElement('tr');
            tr.innerHTML =
                `<td style="font-family:monospace;font-size:.78rem;color:#94A3B8">${r.timestamp || '—'}</td>` +
                `<td style="color:#F8FAFC">${r.type}</td>` +
                `<td style="font-family:monospace;color:#38BDF8">${r.ip || '—'}</td>` +
                `<td><span class="badge-sev ${badgeClass}">${r.severity}</span></td>`;
            tb.appendChild(tr);
        });

        // Timeline — normalise timestamps to YYYY-MM-DD
        const timeline = {};
        rows.forEach(r => {
            const raw = r.timestamp || '';
            let day = 'Unknown';
            // ISO: 2026-07-10T12:00:00
            const isoM = raw.match(/^(\d{4}-\d{2}-\d{2})/);
            // syslog: Jul 10 12:00:01  or  [10/Jul/2026:12:00:00]
            const sysM = raw.match(/(\d{1,2})[\/\s]([A-Za-z]{3})[\/\s](\d{4})/);
            const sysM2 = raw.match(/([A-Za-z]{3})\s+(\d{1,2})/);
            if (isoM) {
                day = isoM[1];
            } else if (sysM) {
                const months = {Jan:'01',Feb:'02',Mar:'03',Apr:'04',May:'05',Jun:'06',Jul:'07',Aug:'08',Sep:'09',Oct:'10',Nov:'11',Dec:'12'};
                day = `${sysM[3]}-${months[sysM[2]] || '01'}-${sysM[1].padStart(2,'0')}`;
            } else if (sysM2) {
                const months = {Jan:'01',Feb:'02',Mar:'03',Apr:'04',May:'05',Jun:'06',Jul:'07',Aug:'08',Sep:'09',Oct:'10',Nov:'11',Dec:'12'};
                const yr = new Date().getFullYear();
                day = `${yr}-${months[sysM2[1]] || '01'}-${sysM2[2].padStart(2,'0')}`;
            }
            timeline[day] = (timeline[day] || 0) + 1;
        });

        const labels = Object.keys(timeline).sort().slice(-30);
        const values = labels.map(l => timeline[l]);

        new Chart(document.getElementById('timelineChart'), {
            type: 'line',
            data: {
                labels,
                datasets: [{
                    label: 'Events',
                    data: values,
                    borderColor: '#EF4444',
                    backgroundColor: 'rgba(239,68,68,0.08)',
                    tension: 0.4,
                    fill: true,
                    pointBackgroundColor: '#EF4444',
                    pointRadius: 3,
                }]
            },
            options: {
                plugins: { legend: { display: false } },
                scales: {
                    x: { ticks: { color: '#64748B', maxRotation: 45 }, grid: { color: 'rgba(255,255,255,0.04)' } },
                    y: { ticks: { color: '#64748B' }, grid: { color: 'rgba(255,255,255,0.04)' }, beginAtZero: true },
                }
            }
        });
    });
});
