document.addEventListener('DOMContentLoaded', () => {
    const load = (ip, sev) => {
        const params = new URLSearchParams();
        if (ip) params.set('ip', ip);
        if (sev) params.set('severity', sev);
        fetch('/api/threats?' + params.toString()).then(r => r.json()).then(rows => {
            const tbody = document.querySelector('#threatTable tbody');
            tbody.innerHTML = '';
            rows.forEach(r => {
                const rec = recommend(r);
                const tr = document.createElement('tr');
                tr.innerHTML = `<td>${r.timestamp || ''}</td><td>${r.ip || ''}</td><td>${r.username || ''}</td><td>${r.type}</td><td>${r.severity}</td><td>${rec}</td>`;
                tbody.appendChild(tr);
            });
        });
    };
    const recommend = (r) => {
        if (r.severity === 'Critical') return 'Isolate host; run full investigation';
        if (r.type.includes('SQL Injection')) return 'Review web input handling; patch and WAF rules';
        if (r.type.includes('Brute Force')) return 'Block IP; enforce MFA and account lockouts';
        return 'Review log and monitor';
    };
    document.getElementById('applyFilters').addEventListener('click', () => {
        const ip = document.getElementById('filterIp').value.trim();
        const sev = document.getElementById('filterSeverity').value;
        load(ip, sev);
    });
    load();
});
