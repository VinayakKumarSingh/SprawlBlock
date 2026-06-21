// SprawlBlock Frontend Dashboard Controller

// Global App State
const state = {
    activeTab: 'overview',
    identities: [],
    filteredIdentities: [],
    incidents: [],
    selectedIdentityId: null,
    selectedIncidentId: null,
    heatmapData: [],
    heatmapFilter: { department: null, platform: null },
    sortKey: 'hybrid_risk_score',
    sortDirection: 'desc',
    pagination: {
        page: 0,
        pageSize: 15
    },
    visNetwork: null, // Vis.js drawer network instance
    mainVisNetwork: null // Vis.js main explorer network instance
};

// Initialization on DOM load
document.addEventListener('DOMContentLoaded', () => {
    initApp();
});

function initApp() {
    setupTabNavigation();
    setupEventHandlers();
    loadDashboardData();
}

// 1. Tab Navigation Routing
function setupTabNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    const viewTitle = document.getElementById('view-title');
    
    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const targetTab = item.getAttribute('data-tab');
            
            // Toggle active nav class
            navItems.forEach(i => i.classList.remove('active'));
            item.classList.add('active');
            
            // Toggle active content pane
            document.querySelectorAll('.tab-pane').forEach(pane => {
                pane.classList.remove('active');
            });
            document.getElementById(`tab-${targetTab}`).classList.add('active');
            
            // Update Title
            state.activeTab = targetTab;
            if (targetTab === 'overview') viewTitle.textContent = "Overview Dashboard";
            else if (targetTab === 'incidents') viewTitle.textContent = "Incident Remediation Console";
            else if (targetTab === 'heatmap') viewTitle.textContent = "Cross-Platform Privilege Heatmap";
            else if (targetTab === 'risk-list') viewTitle.textContent = "Identity Risk Directory";
            else if (targetTab === 'graph-explorer') viewTitle.textContent = "Entitlement Graph Explorer";
            
            // Perform tab-specific refreshes
            if (targetTab === 'overview') {
                loadOverviewData();
            } else if (targetTab === 'incidents') {
                loadIncidentsData();
            } else if (targetTab === 'heatmap') {
                loadHeatmapData();
            } else if (targetTab === 'risk-list') {
                loadRiskListData();
            } else if (targetTab === 'graph-explorer') {
                loadGraphExplorerData();
            }
        });
    });

    // View All links redirection
    document.querySelectorAll('.view-all-trigger').forEach(trigger => {
        trigger.addEventListener('click', () => {
            const targetTab = trigger.getAttribute('data-target-tab');
            const correspondingNav = document.querySelector(`.nav-item[data-tab="${targetTab}"]`);
            if (correspondingNav) {
                correspondingNav.click();
            }
        });
    });
}

// 2. Attach Event Handlers
function setupEventHandlers() {
    // Risk List Filtering
    const searchInput = document.getElementById('input-search');
    const deptSelect = document.getElementById('select-dept');
    const statusSelect = document.getElementById('select-status');
    
    if (searchInput) searchInput.addEventListener('input', applyRiskFilters);
    if (deptSelect) deptSelect.addEventListener('change', applyRiskFilters);
    if (statusSelect) statusSelect.addEventListener('change', applyRiskFilters);
    
    // Risk List Table Headers (Sorting)
    const sortHeaders = document.querySelectorAll('#table-risk-list th.sortable');
    sortHeaders.forEach(th => {
        th.addEventListener('click', () => {
            const key = th.getAttribute('data-sort');
            
            if (state.sortKey === key) {
                state.sortDirection = state.sortDirection === 'asc' ? 'desc' : 'asc';
            } else {
                state.sortKey = key;
                state.sortDirection = 'desc'; // default to high risk
            }
            
            // Toggle active classes on headers
            sortHeaders.forEach(h => {
                h.classList.remove('active', 'asc', 'desc');
            });
            th.classList.add('active', state.sortDirection);
            
            sortFilteredIdentities();
            renderRiskListTable();
        });
    });
    
    // Pagination Controls
    document.getElementById('btn-prev-page').addEventListener('click', () => {
        if (state.pagination.page > 0) {
            state.pagination.page--;
            renderRiskListTable();
        }
    });
    
    document.getElementById('btn-next-page').addEventListener('click', () => {
        const totalPages = Math.ceil(state.filteredIdentities.length / state.pagination.pageSize);
        if (state.pagination.page < totalPages - 1) {
            state.pagination.page++;
            renderRiskListTable();
        }
    });
    
    // Drawer Close
    document.getElementById('btn-close-drawer').addEventListener('click', closeDrawer);
    document.querySelector('.drawer-overlay').addEventListener('click', closeDrawer);
    
    // Drawer Tabs
    const drawerTabBtns = document.querySelectorAll('.drawer-tab-btn');
    drawerTabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            drawerTabBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            const targetTab = btn.getAttribute('data-drawer-tab');
            document.querySelectorAll('.drawer-tab-pane').forEach(pane => {
                pane.classList.remove('active');
            });
            document.getElementById(`drawer-tab-${targetTab}`).classList.add('active');
            
            // Fit graph network if switched to graph tab
            if (targetTab === 'graph' && state.visNetwork) {
                setTimeout(() => {
                    state.visNetwork.fit();
                }, 100);
            }
        });
    });
    
    // vis.js Toolbar fit
    document.getElementById('btn-fit-graph').addEventListener('click', () => {
        if (state.visNetwork) {
            state.visNetwork.fit();
        }
    });
    
    // Apply Incident Remediation
    document.getElementById('btn-remediate').addEventListener('click', () => {
        if (state.selectedIncidentId) {
            executeRemediation(state.selectedIncidentId);
        }
    });
    
    // Reset Simulation
    document.getElementById('btn-run-simulation').addEventListener('click', executeSimulationReset);
    
    // Close Remediation Modal
    document.getElementById('btn-close-remediation-modal').addEventListener('click', () => {
        document.getElementById('modal-remediation').classList.remove('open');
    });
    
    // Clear Heatmap filter
    document.getElementById('btn-clear-heatmap-filter').addEventListener('click', () => {
        state.heatmapFilter = { department: null, platform: null };
        document.getElementById('heatmap-filtered-card').classList.add('hidden');
        document.querySelectorAll('.heatmap-cell').forEach(c => c.classList.remove('active-filter'));
    });

    // Graph Explorer User Selection Change
    const graphUserSelect = document.getElementById('select-graph-user');
    if (graphUserSelect) {
        graphUserSelect.addEventListener('change', (e) => {
            renderMainGraphExplorer(e.target.value);
        });
    }

    // Graph Explorer fit button
    const fitMainGraphBtn = document.getElementById('btn-fit-main-graph');
    if (fitMainGraphBtn) {
        fitMainGraphBtn.addEventListener('click', () => {
            if (state.mainVisNetwork) {
                state.mainVisNetwork.fit();
            }
        });
    }
}

// 3. API Loaders
async function apiFetch(url, options = {}) {
    try {
        const response = await fetch(url, options);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    } catch (e) {
        console.error("API fetching error:", e);
        showBannerNotification(`API request failed: ${e.message}`, 'error');
        return null;
    }
}

// Banner alerts
function showBannerNotification(message, type = 'info') {
    const header = document.querySelector('.main-header');
    const existingBanner = document.querySelector('.banner-notification');
    if (existingBanner) existingBanner.remove();
    
    const banner = document.createElement('div');
    banner.className = `banner-notification banner-${type}`;
    banner.style.padding = '8px 16px';
    banner.style.backgroundColor = type === 'error' ? '#991b1b' : '#065f46';
    banner.style.color = '#f8fafc';
    banner.style.fontSize = '12.5px';
    banner.style.fontWeight = '500';
    banner.style.display = 'flex';
    banner.style.justifyContent = 'space-between';
    banner.style.alignItems = 'center';
    banner.style.borderBottom = '1px solid rgba(255,255,255,0.1)';
    
    banner.innerHTML = `
        <span>${message}</span>
        <button style="background:none; border:none; color:inherit; cursor:pointer; font-weight:bold;" onclick="this.parentElement.remove()">✕</button>
    `;
    header.parentNode.insertBefore(banner, header.nextSibling);
    
    setTimeout(() => {
        banner.remove();
    }, 6000);
}

// Load global counts
async function loadDashboardData() {
    const summary = await apiFetch('/api/summary');
    if (summary) {
        document.getElementById('stat-identities').textContent = summary.total_identities;
        document.getElementById('stat-incidents').textContent = summary.total_incidents;
        document.getElementById('stat-critical-incidents').textContent = summary.critical_incidents;
        document.getElementById('stat-avg-risk').textContent = summary.avg_risk_score;
        
        const accounts = summary.platform_active_accounts;
        document.getElementById('stat-accounts').textContent = accounts.AD + accounts.AWS + accounts.Okta;
        document.getElementById('stat-accounts-detail').innerHTML = `AD: <strong>${accounts.AD}</strong> | AWS: <strong>${accounts.AWS}</strong> | Okta: <strong>${accounts.Okta}</strong>`;
    }
    
    // Trigger initial tab load
    if (state.activeTab === 'overview') {
        loadOverviewData();
    }
}

// OVERVIEW VIEW LOADER
async function loadOverviewData() {
    // Refresh Summary Statistics
    loadDashboardData();
    
    // Load top 5 riskiest identities
    const identities = await apiFetch('/api/identities');
    if (identities) {
        state.identities = identities;
        
        const tbody = document.querySelector('#table-overview-risks tbody');
        tbody.innerHTML = '';
        
        // Take top 5
        const top5 = identities.slice(0, 5);
        if (top5.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted">No high-risk identities found.</td></tr>`;
        } else {
            top5.forEach(user => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><strong>${user.emp_id}</strong></td>
                    <td>${user.title}</td>
                    <td>${user.department}</td>
                    <td>${user.ml_risk_score}</td>
                    <td><span class="badge ${getRiskBadgeClass(user.hybrid_risk_score)}">${user.hybrid_risk_score}</span></td>
                `;
                tr.addEventListener('click', () => openIdentityDrawer(user.emp_id));
                tbody.appendChild(tr);
            });
        }
    }
    
    // Populate mini-heatmap summary widget
    const heatmap = await apiFetch('/api/heatmap');
    if (heatmap) {
        const miniContainer = document.getElementById('mini-heatmap-container');
        miniContainer.innerHTML = '';
        
        // Pick three interesting departments to showcase
        const sampleDepts = ["IT Security", "Marketing", "Engineering"];
        sampleDepts.forEach(dept => {
            const data = heatmap.find(h => h.department === dept);
            if (data) {
                // Calculate average risk score across the three platforms
                const avgRisk = parseFloat(((data.AD.avg_risk_score + data.AWS.avg_risk_score + data.Okta.avg_risk_score) / 3).toFixed(1));
                const activeCount = data.AD.active_accounts + data.AWS.active_accounts + data.Okta.active_accounts;
                
                const box = document.createElement('div');
                box.className = 'mini-heatmap-cell';
                
                // Color boundaries
                let textClass = 'text-success';
                if (avgRisk >= 80) textClass = 'text-critical';
                else if (avgRisk >= 50) textClass = 'text-warning';
                
                box.innerHTML = `
                    <span class="val ${textClass}">${avgRisk}</span>
                    <span class="lbl">${dept}</span>
                    <span class="text-xs text-muted" style="display:block; margin-top:2px;">${activeCount} Accounts</span>
                `;
                miniContainer.appendChild(box);
            }
        });
    }
}

// RISK LIST VIEW LOADER
async function loadRiskListData() {
    const identities = await apiFetch('/api/identities');
    if (identities) {
        state.identities = identities;
        applyRiskFilters();
    }
}

// Filtering & sorting identity lists
function applyRiskFilters() {
    const searchVal = document.getElementById('input-search').value.toLowerCase().trim();
    const deptVal = document.getElementById('select-dept').value;
    const statusVal = document.getElementById('select-status').value;
    
    state.filteredIdentities = state.identities.filter(user => {
        // Search matches ID, Title, or Department
        const matchesSearch = !searchVal || 
            user.emp_id.toLowerCase().includes(searchVal) ||
            user.title.toLowerCase().includes(searchVal) ||
            user.department.toLowerCase().includes(searchVal);
            
        // Department dropdown filter
        const matchesDept = !deptVal || user.department === deptVal;
        
        // Compliance Violation Filter
        let matchesStatus = true;
        if (statusVal === 'Anomalies') {
            matchesStatus = user.framework_violations && user.framework_violations.length > 0;
        } else if (statusVal === 'Clean') {
            matchesStatus = !user.framework_violations || user.framework_violations.length === 0;
        }
        
        return matchesSearch && matchesDept && matchesStatus;
    });
    
    sortFilteredIdentities();
    state.pagination.page = 0; // reset to first page
    renderRiskListTable();
}

function sortFilteredIdentities() {
    const key = state.sortKey;
    const dir = state.sortDirection === 'asc' ? 1 : -1;
    
    state.filteredIdentities.sort((a, b) => {
        let valA = a[key];
        let valB = b[key];
        
        // Handle numeric parsing
        if (typeof valA === 'string' && !isNaN(valA)) valA = parseFloat(valA);
        if (typeof valB === 'string' && !isNaN(valB)) valB = parseFloat(valB);
        
        if (valA < valB) return -1 * dir;
        if (valA > valB) return 1 * dir;
        return 0;
    });
}

function renderRiskListTable() {
    const tbody = document.querySelector('#table-risk-list tbody');
    tbody.innerHTML = '';
    
    const count = state.filteredIdentities.length;
    const page = state.pagination.page;
    const size = state.pagination.pageSize;
    
    const startIdx = page * size;
    const endIdx = Math.min(startIdx + size, count);
    
    document.getElementById('pagination-info').textContent = count > 0 
        ? `Showing ${startIdx + 1}-${endIdx} of ${count}` 
        : 'Showing 0-0 of 0';
        
    // Disable/enable pagination buttons
    document.getElementById('btn-prev-page').disabled = (page === 0);
    const totalPages = Math.ceil(count / size);
    document.getElementById('btn-next-page').disabled = (page >= totalPages - 1 || totalPages <= 1);
    
    const pageSlice = state.filteredIdentities.slice(startIdx, endIdx);
    
    if (pageSlice.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted">No records match criteria.</td></tr>`;
        return;
    }
    
    pageSlice.forEach(user => {
        const tr = document.createElement('tr');
        if (state.selectedIdentityId === user.emp_id) {
            tr.className = 'selected';
        }
        
        // Format last login dates
        const dateStr = user.last_login ? user.last_login.split('T')[0] : 'Never';
        
        // Append indicators if user has compliance violations
        const violationsBadges = user.framework_violations && user.framework_violations.length > 0 
            ? `<span class="badge badge-critical" style="margin-left:8px; font-size:9px; padding:1px 4px;">Anomalies</span>`
            : '';
            
        tr.innerHTML = `
            <td><strong>${user.emp_id}</strong>${violationsBadges}</td>
            <td>${user.title}</td>
            <td>${user.department}</td>
            <td>${dateStr}</td>
            <td>${user.ml_risk_score}</td>
            <td><span class="badge ${getRiskBadgeClass(user.hybrid_risk_score)}">${user.hybrid_risk_score}</span></td>
        `;
        
        tr.addEventListener('click', () => {
            // Select row
            document.querySelectorAll('#table-risk-list tr').forEach(r => r.classList.remove('selected'));
            tr.classList.add('selected');
            state.selectedIdentityId = user.emp_id;
            
            // Slide open detail drawer
            openIdentityDrawer(user.emp_id);
        });
        tbody.appendChild(tr);
    });
}

function getRiskBadgeClass(score) {
    if (score >= 85) return 'badge-critical';
    if (score >= 70) return 'badge-high';
    if (score >= 40) return 'badge-medium';
    return 'badge-low';
}

function getRiskColorCode(score) {
    if (score >= 85) return '#991b1b'; // Red
    if (score >= 70) return '#9a3412'; // Orange
    if (score >= 40) return '#92400e'; // Amber
    if (score > 0) return '#065f46';  // Green
    return '#1e293b';                  // Slate
}

// 4. IDENTITY DRAWER DETAILED INSPECTION
async function openIdentityDrawer(empId) {
    state.selectedIdentityId = empId;
    
    // Display container
    const drawer = document.getElementById('identity-detail-drawer');
    drawer.classList.add('open');
    
    // Set loading state in drawer tabs
    document.getElementById('drawer-user-id').textContent = empId;
    document.getElementById('drawer-user-badge').textContent = 'Loading...';
    document.getElementById('drawer-user-badge').className = 'badge';
    
    const details = await apiFetch(`/api/identity/${empId}`);
    if (!details) {
        closeDrawer();
        return;
    }
    
    const meta = details.metadata;
    const risk = details.risk_details;
    
    // Update Badge
    const score = risk.hybrid_risk_score || 0.0;
    const badge = document.getElementById('drawer-user-badge');
    badge.textContent = `Score: ${score}`;
    badge.className = `badge ${getRiskBadgeClass(score)}`;
    
    // Profile Metadata Tab
    document.getElementById('drawer-meta-title').textContent = meta.title || 'N/A';
    document.getElementById('drawer-meta-department').textContent = meta.department || 'N/A';
    document.getElementById('drawer-meta-hr-status').textContent = meta.hr_status || 'N/A';
    
    const lastLoginStr = meta.last_login ? meta.last_login.replace('T', ' ').replace('Z', '') : 'Never';
    document.getElementById('drawer-meta-last-login').textContent = lastLoginStr;
    
    // AWS / AD / Okta accounts status row
    updatePlatformCard('ad', meta.ad_id, meta.ad_status);
    updatePlatformCard('aws', meta.aws_id, meta.aws_status);
    updatePlatformCard('okta', meta.okta_id, meta.okta_status);
    
    // ML Features
    const feats = risk.features || { access_frequency: 0, platform_spread: 0, privilege_to_usage_ratio: 0, total_privileges: 0 };
    document.getElementById('drawer-feat-freq').textContent = feats.access_frequency;
    document.getElementById('drawer-feat-spread').textContent = feats.platform_spread;
    document.getElementById('drawer-feat-ratio').textContent = feats.privilege_to_usage_ratio;
    document.getElementById('drawer-feat-total').textContent = feats.total_privileges;
    
    // Violations list
    const violationsContainer = document.getElementById('drawer-violations-list');
    violationsContainer.innerHTML = '';
    const violations = risk.framework_violations || [];
    if (violations.length === 0) {
        violationsContainer.innerHTML = `<span class="text-muted text-sm">No compliance framework alerts detected for this identity.</span>`;
    } else {
        violations.forEach(v => {
            const vDiv = document.createElement('div');
            vDiv.className = 'violation-tag';
            vDiv.textContent = `⚠️ Flagged Violation: ${v}`;
            violationsContainer.appendChild(vDiv);
        });
    }
    
    // Audit Log Tab
    const auditTbody = document.querySelector('#table-user-audit tbody');
    auditTbody.innerHTML = '';
    const events = details.events || [];
    
    if (events.length === 0) {
        auditTbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted">No audit events logged for this identity.</td></tr>`;
    } else {
        events.forEach(ev => {
            const evTr = document.createElement('tr');
            const stamp = ev.timestamp ? ev.timestamp.replace('T', ' ').replace('Z', '') : '';
            const statusClass = ev.status === 'Success' ? 'text-success' : 'text-critical';
            
            evTr.innerHTML = `
                <td class="text-xs">${stamp}</td>
                <td><strong>${ev.platform}</strong></td>
                <td class="text-xs">${ev.platform_id}</td>
                <td class="text-xs"><code>${ev.action}</code></td>
                <td class="${statusClass}"><strong>${ev.status}</strong></td>
            `;
            auditTbody.appendChild(evTr);
        });
    }
    
    // Render network graph
    renderVisNetworkGraph(details.graph, empId);
}

function updatePlatformCard(platformKey, accountId, status) {
    const card = document.getElementById(`card-status-${platformKey}`);
    const idEl = document.getElementById(`drawer-acct-${platformKey}`);
    const statusEl = document.getElementById(`drawer-status-${platformKey}`);
    
    if (!accountId) {
        card.className = 'platform-status-card disabled-acct';
        idEl.textContent = 'None Assigned';
        statusEl.textContent = 'UNMAPPED';
        statusEl.className = 'status-indicator text-muted';
    } else {
        idEl.textContent = accountId;
        statusEl.textContent = status.toUpperCase();
        
        if (status === 'Active') {
            card.className = 'platform-status-card active-acct';
            statusEl.className = 'status-indicator text-success';
        } else {
            card.className = 'platform-status-card disabled-acct';
            statusEl.className = 'status-indicator text-muted';
        }
    }
}

function closeDrawer() {
    document.getElementById('identity-detail-drawer').classList.remove('open');
    state.selectedIdentityId = null;
    
    // Reset active drawer tab to profile
    document.querySelectorAll('.drawer-tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelector('.drawer-tab-btn[data-drawer-tab="profile"]').classList.add('active');
    document.querySelectorAll('.drawer-tab-pane').forEach(pane => pane.classList.remove('active'));
    document.getElementById('drawer-tab-profile').classList.add('active');
    
    // Destroy vis network if exists
    if (state.visNetwork) {
        state.visNetwork.destroy();
        state.visNetwork = null;
    }
}

// 5. VIS.JS NETWORK ENTITLEMENT GRAPH
function renderVisNetworkGraph(graphData, rootEmpId) {
    const canvasContainer = document.getElementById('vis-graph-canvas');
    canvasContainer.innerHTML = ''; // Clear loader
    
    if (!graphData || !graphData.nodes || graphData.nodes.length === 0) {
        canvasContainer.innerHTML = `<div class="empty-state">No graph nodes available.</div>`;
        document.getElementById('graph-node-count').textContent = "0 nodes, 0 edges";
        return;
    }
    
    document.getElementById('graph-node-count').textContent = `${graphData.nodes.length} nodes, ${graphData.edges.length} edges`;
    
    // Map raw data into Vis.js Nodes
    const visNodes = graphData.nodes.map(n => {
        let nodeColor = { background: '#1e293b', border: '#334155' };
        let nodeShape = 'box';
        let borderWidth = 1.5;
        
        if (n.type === 'identity') {
            nodeShape = 'ellipse';
            nodeColor = { background: '#2563eb', border: '#1d4ed8' }; // Electric Blue
            borderWidth = 2.5;
        } else if (n.type === 'account') {
            nodeShape = 'box';
            
            // Base border based on status
            const borderCol = n.status === 'Active' ? '#10b981' : '#64748b';
            
            if (n.platform === 'AD') {
                nodeColor = { background: '#1e3a8a', border: borderCol }; // Dark blue
            } else if (n.platform === 'AWS') {
                nodeColor = { background: '#7c2d12', border: borderCol }; // Orange/brown
            } else {
                nodeColor = { background: '#0f172a', border: borderCol }; // Slate
            }
            borderWidth = 2;
        } else if (n.type === 'group') {
            nodeShape = 'hexagon';
            nodeColor = { background: '#5b21b6', border: '#7c3aed' }; // Purple
        } else if (n.type === 'permission') {
            nodeShape = 'diamond';
            
            // Admin permissions color high contrast
            const isAdmin = n.label.toLowerCase().includes('admin');
            nodeColor = isAdmin 
                ? { background: '#7f1d1d', border: '#ef4444' } // High risk red
                : { background: '#064e3b', border: '#34d399' }; // Clean green
        }
        
        // Multi-line formatting support
        return {
            id: n.id,
            label: n.label,
            shape: nodeShape,
            color: {
                background: nodeColor.background,
                border: nodeColor.border,
                highlight: {
                    background: '#4f46e5',
                    border: '#6366f1'
                }
            },
            borderWidth: borderWidth,
            font: {
                color: '#f8fafc',
                size: 11,
                face: 'Inter, system-ui'
            },
            margin: 10
        };
    });
    
    // Map edges
    const visEdges = graphData.edges.map(e => {
        let edgeColor = '#475569';
        let edgeDashes = false;
        
        if (e.type === 'entitlement') {
            edgeColor = '#f43f5e'; // Red path to privilege
        } else if (e.type === 'mapping') {
            edgeColor = '#818cf8'; // Violet mappings
            edgeDashes = true;
        }
        
        return {
            from: e.from,
            to: e.to,
            color: edgeColor,
            arrows: {
                to: { enabled: true, scaleFactor: 0.8 }
            },
            dashes: edgeDashes,
            width: 1.5
        };
    });
    
    const data = {
        nodes: new vis.DataSet(visNodes),
        edges: new vis.DataSet(visEdges)
    };
    
    const options = {
        nodes: {
            margin: 8,
            shadow: false
        },
        edges: {
            smooth: {
                type: 'cubicBezier',
                forceDirection: 'vertical',
                roundness: 0.4
            }
        },
        physics: {
            hierarchicalRepulsion: {
                nodeDistance: 130
            },
            stabilization: {
                iterations: 150
            }
        },
        layout: {
            hierarchical: {
                direction: 'UD', // Up-Down hierarchy layout
                sortMethod: 'directed',
                nodeSpacing: 160,
                levelCalculationMethod: 'hubsize'
            }
        },
        interaction: {
            hover: true,
            zoomView: true,
            dragView: true
        }
    };
    
    state.visNetwork = new vis.Network(canvasContainer, data, options);
    
    // Add fit callback
    state.visNetwork.once('stabilizationFinished', () => {
        state.visNetwork.fit();
    });
}

// 6. PRIVILEGE HEATMAP VIEW LOADER
async function loadHeatmapData() {
    const data = await apiFetch('/api/heatmap');
    if (data) {
        state.heatmapData = data;
        renderHeatmap();
    }
}

function renderHeatmap() {
    const tbody = document.getElementById('heatmap-tbody');
    tbody.innerHTML = '';
    
    const platforms = ["AD", "AWS", "Okta"];
    
    state.heatmapData.forEach(row => {
        const tr = document.createElement('tr');
        
        // Department Name cell
        const tdDept = document.createElement('td');
        tdDept.innerHTML = `<strong>${row.department}</strong>`;
        tr.appendChild(tdDept);
        
        // Platform Matrix Cells
        platforms.forEach(plat => {
            const cellData = row[plat];
            const tdCell = document.createElement('td');
            
            tdCell.className = 'heatmap-cell';
            
            // Check if cell is active filter
            if (state.heatmapFilter.department === row.department && state.heatmapFilter.platform === plat) {
                tdCell.classList.add('active-filter');
            }
            
            // Color backgrounds based on risk score thresholds
            const risk = cellData.avg_risk_score;
            tdCell.style.backgroundColor = getRiskColorCode(risk);
            
            // Populate metrics inside cells
            tdCell.innerHTML = `
                <span class="heatmap-cell-value">${cellData.active_accounts} Accounts</span>
                <span class="heatmap-cell-label">${risk > 0 ? 'Risk: ' + risk : 'Clean'}</span>
            `;
            
            // Click triggers table filter below
            tdCell.addEventListener('click', () => {
                document.querySelectorAll('.heatmap-cell').forEach(c => c.classList.remove('active-filter'));
                
                if (state.heatmapFilter.department === row.department && state.heatmapFilter.platform === plat) {
                    // Toggle Off
                    state.heatmapFilter = { department: null, platform: null };
                    document.getElementById('heatmap-filtered-card').classList.add('hidden');
                } else {
                    // Toggle On
                    state.heatmapFilter = { department: row.department, platform: plat };
                    tdCell.classList.add('active-filter');
                    renderHeatmapFilteredUsers(row.department, plat);
                }
            });
            
            tr.appendChild(tdCell);
        });
        
        tbody.appendChild(tr);
    });
}

function renderHeatmapFilteredUsers(department, platform) {
    const container = document.getElementById('heatmap-filtered-card');
    const title = document.getElementById('heatmap-filter-title');
    const tbody = document.getElementById('heatmap-users-tbody');
    
    title.textContent = `Department Matrix view: ${department} ⇾ ${platform} Integrations`;
    tbody.innerHTML = '';
    
    // Filter global users cache
    const statusCol = `${platform.toLowerCase()}_status`;
    const filtered = state.identities.filter(user => {
        return user.department === department && user[statusCol] === 'Active';
    });
    
    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted">No active employees mapped to ${platform} in ${department}.</td></tr>`;
    } else {
        filtered.forEach(user => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><strong>${user.emp_id}</strong></td>
                <td>${user.title}</td>
                <td><code>${user.ad_id || 'N/A'}</code></td>
                <td><code>${user.aws_id || 'N/A'}</code></td>
                <td><code>${user.okta_id || 'N/A'}</code></td>
                <td><span class="badge ${getRiskBadgeClass(user.hybrid_risk_score)}">${user.hybrid_risk_score}</span></td>
            `;
            tr.addEventListener('click', () => openIdentityDrawer(user.emp_id));
            tbody.appendChild(tr);
        });
    }
    
    container.classList.remove('hidden');
}

// 7. INCIDENTS VIEW LOADER
async function loadIncidentsData() {
    const incidents = await apiFetch('/api/incidents');
    if (incidents) {
        state.incidents = incidents;
        renderIncidentsList();
        
        // Maintain selection if exists, else load first one
        if (state.selectedIncidentId) {
            selectIncident(state.selectedIncidentId);
        } else if (incidents.length > 0) {
            selectIncident(incidents[0].incident_id);
        } else {
            showIncidentEmptyState();
        }
    }
}

function renderIncidentsList() {
    const container = document.getElementById('incident-list-container');
    container.innerHTML = '';
    
    if (state.incidents.length === 0) {
        container.innerHTML = `<div class="text-center text-muted p-4">No active incident clusters. System secure.</div>`;
        return;
    }
    
    state.incidents.forEach(inc => {
        const card = document.createElement('div');
        card.className = 'incident-card';
        if (state.selectedIncidentId === inc.incident_id) {
            card.classList.add('active');
        }
        
        const sevClass = inc.severity === 'CRITICAL' ? 'text-critical' : 'text-warning';
        
        card.innerHTML = `
            <div class="incident-card-header">
                <span class="badge text-xs" style="background-color:rgba(255,255,255,0.05); color:var(--text-secondary);">${inc.incident_id}</span>
                <span class="badge ${inc.severity === 'CRITICAL' ? 'badge-critical' : 'badge-high'}">${inc.severity}</span>
            </div>
            <h4>${inc.title}</h4>
            <div class="incident-card-footer">
                <span>Affected Users: <strong>${inc.affected_identities_count}</strong></span>
            </div>
        `;
        
        card.addEventListener('click', () => {
            selectIncident(inc.incident_id);
        });
        
        container.appendChild(card);
    });
}

function selectIncident(incidentId) {
    state.selectedIncidentId = incidentId;
    
    // Highlight sidebar entry
    document.querySelectorAll('.incident-card').forEach(card => {
        card.classList.remove('active');
    });
    
    // Render sidebar active class
    const sidebarEntries = document.querySelectorAll('.incident-card');
    state.incidents.forEach((inc, idx) => {
        if (inc.incident_id === incidentId && sidebarEntries[idx]) {
            sidebarEntries[idx].classList.add('active');
        }
    });
    
    const incident = state.incidents.find(i => i.incident_id === incidentId);
    if (!incident) {
        showIncidentEmptyState();
        return;
    }
    
    // Show drilldown content
    document.getElementById('incident-empty-state').classList.add('hidden');
    document.getElementById('incident-detail-content').classList.remove('hidden');
    
    // Map details
    document.getElementById('incident-detail-id').textContent = incident.incident_id;
    const sevBadge = document.getElementById('incident-detail-severity');
    sevBadge.textContent = incident.severity;
    sevBadge.className = `badge ${incident.severity === 'CRITICAL' ? 'badge-critical' : 'badge-high'}`;
    
    document.getElementById('incident-detail-title').textContent = incident.title;
    
    // Render Markdown summary from LLM
    document.getElementById('incident-detail-narrative').innerHTML = marked.parse(incident.llm_executive_summary || '');
    
    // Blast radius users list
    const tbody = document.querySelector('#table-incident-users tbody');
    tbody.innerHTML = '';
    
    const affected = incident.affected_users || [];
    document.getElementById('blast-radius-title').textContent = `Blast Radius (${affected.length} Affected Identities)`;
    
    affected.forEach(user => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><strong>${user.emp_id}</strong></td>
            <td><span class="badge ${getRiskBadgeClass(user.hybrid_risk_score)}">${user.hybrid_risk_score}</span></td>
            <td>${user.features.access_frequency}</td>
            <td>${user.features.platform_spread}</td>
            <td>${user.features.total_privileges}</td>
            <td><button class="btn btn-secondary btn-sm inspect-btn">Inspect</button></td>
        `;
        
        tr.querySelector('.inspect-btn').addEventListener('click', (e) => {
            e.stopPropagation();
            openIdentityDrawer(user.emp_id);
        });
        tbody.appendChild(tr);
    });
}

function showIncidentEmptyState() {
    document.getElementById('incident-empty-state').classList.remove('hidden');
    document.getElementById('incident-detail-content').classList.add('hidden');
    state.selectedIncidentId = null;
}

// 8. INCIDENT REMEDIATION TRANSACTION EXECUTION
async function executeRemediation(incidentId) {
    // Open Log Console Modal
    const modal = document.getElementById('modal-remediation');
    modal.classList.add('open');
    
    const logConsole = document.getElementById('remediation-log-console');
    logConsole.innerHTML = '';
    
    const spinner = document.getElementById('remediation-spinner');
    spinner.classList.remove('hidden');
    
    const closeBtn = document.getElementById('btn-close-remediation-modal');
    closeBtn.disabled = true;
    
    // Print initiation log
    writeConsoleLog(logConsole, `[!] Initializing remediation sequence for ${incidentId}...`);
    writeConsoleLog(logConsole, `[*] Querying active platform target configurations...`);
    
    // Execute POST API
    const response = await fetch(`/api/remediate/${incidentId}`, { method: 'POST' });
    const result = await response.json();
    
    if (result && result.success) {
        // Stream logs to console
        const logs = result.logs || [];
        for (let i = 0; i < logs.length; i++) {
            await sleep(600); // simulate log reading/processing animation
            writeConsoleLog(logConsole, `[+] ${logs[i]}`);
        }
        await sleep(400);
        writeConsoleLog(logConsole, `[✓] Remediation sequence execution completed successfully!`, 'success');
        
        // Refresh local memory and UI
        await reloadDashboardOnRemediation();
        
        // Deselect or switch
        state.selectedIncidentId = null;
        loadIncidentsData();
    } else {
        const errMsg = result ? result.error : "Unknown network error";
        writeConsoleLog(logConsole, `[✗] ERROR: Remediation failed: ${errMsg}`, 'error');
    }
    
    // Finish sequence
    spinner.classList.add('hidden');
    closeBtn.disabled = false;
}

// 9. DATABASE SIMULATION RESET
async function executeSimulationReset() {
    const confirmReset = confirm("Are you sure you want to reset the simulation database? This will restore all 300 identities to their original generated states and wipe out any remediation actions applied.");
    if (!confirmReset) return;
    
    const modal = document.getElementById('modal-remediation');
    const header = modal.querySelector('h3');
    header.textContent = "Resetting simulation database...";
    
    modal.classList.add('open');
    
    const logConsole = document.getElementById('remediation-log-console');
    logConsole.innerHTML = '';
    
    const spinner = document.getElementById('remediation-spinner');
    spinner.classList.remove('hidden');
    
    const closeBtn = document.getElementById('btn-close-remediation-modal');
    closeBtn.disabled = true;
    
    writeConsoleLog(logConsole, `[!] Loading dataset constraints generator...`);
    
    const response = await fetch(`/api/run-simulation`, { method: 'POST' });
    const result = await response.json();
    
    if (result && result.success) {
        const logs = result.logs || [];
        for (let i = 0; i < logs.length; i++) {
            await sleep(500);
            writeConsoleLog(logConsole, `[+] ${logs[i]}`);
        }
        await sleep(300);
        writeConsoleLog(logConsole, `[✓] Simulation database reset completed!`, 'success');
        
        // Re-align variables
        state.selectedIdentityId = null;
        state.selectedIncidentId = null;
        
        // Force refresh all views
        await loadDashboardData();
        if (state.activeTab === 'overview') loadOverviewData();
        else if (state.activeTab === 'incidents') loadIncidentsData();
        else if (state.activeTab === 'heatmap') loadHeatmapData();
        else if (state.activeTab === 'risk-list') loadRiskListData();
    } else {
        const errMsg = result ? result.error : "Unknown network error";
        writeConsoleLog(logConsole, `[✗] ERROR: Simulation reset failed: ${errMsg}`, 'error');
    }
    
    header.textContent = "Applying Remediation Playbook...";
    spinner.classList.add('hidden');
    closeBtn.disabled = false;
}

// Helpers
function writeConsoleLog(consoleEl, text, type = 'info') {
    const entry = document.createElement('div');
    entry.className = `log-entry ${type === 'error' ? 'error' : ''}`;
    entry.textContent = text;
    consoleEl.appendChild(entry);
    consoleEl.scrollTop = consoleEl.scrollHeight;
}

async function reloadDashboardOnRemediation() {
    // Re-fetch caches
    const summary = await apiFetch('/api/summary');
    if (summary) {
        document.getElementById('stat-identities').textContent = summary.total_identities;
        document.getElementById('stat-incidents').textContent = summary.total_incidents;
        document.getElementById('stat-critical-incidents').textContent = summary.critical_incidents;
        document.getElementById('stat-avg-risk').textContent = summary.avg_risk_score;
        
        const accounts = summary.platform_active_accounts;
        document.getElementById('stat-accounts').textContent = accounts.AD + accounts.AWS + accounts.Okta;
        document.getElementById('stat-accounts-detail').innerHTML = `AD: <strong>${accounts.AD}</strong> | AWS: <strong>${accounts.AWS}</strong> | Okta: <strong>${accounts.Okta}</strong>`;
    }
    
    // Fetch fresh identities list
    const identities = await apiFetch('/api/identities');
    if (identities) {
        state.identities = identities;
        // recalculate filters in background
        if (state.activeTab === 'risk-list') {
            applyRiskFilters();
        } else if (state.activeTab === 'graph-explorer') {
            const currentSel = document.getElementById('select-graph-user').value;
            loadGraphExplorerData();
            if (currentSel) {
                document.getElementById('select-graph-user').value = currentSel;
                renderMainGraphExplorer(currentSel);
            }
        }
    }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// 10. MAIN GRAPH EXPLORER MODULE
async function loadGraphExplorerData() {
    const identities = await apiFetch('/api/identities');
    if (!identities) return;
    
    state.identities = identities;
    const select = document.getElementById('select-graph-user');
    const currentValue = select.value;
    
    select.innerHTML = '<option value="">Choose an Employee...</option>';
    
    // Sort identities by hybrid risk score descending
    const sorted = [...identities].sort((a, b) => b.hybrid_risk_score - a.hybrid_risk_score);
    
    sorted.forEach(user => {
        const opt = document.createElement('option');
        opt.value = user.emp_id;
        opt.textContent = `${user.emp_id} - ${user.title} (${user.department}) - Risk: ${user.hybrid_risk_score}`;
        select.appendChild(opt);
    });
    
    if (currentValue) {
        select.value = currentValue;
    }
    
    // Populate Quick Links with top 4 riskiest identities
    const quickLinksContainer = document.getElementById('graph-quick-links');
    quickLinksContainer.innerHTML = '';
    
    const top4 = sorted.slice(0, 4);
    top4.forEach(user => {
        const btn = document.createElement('button');
        btn.className = `btn btn-secondary btn-sm ${getRiskBadgeClass(user.hybrid_risk_score)}`;
        btn.style.color = '#f8fafc';
        btn.style.border = '1px solid var(--border-color)';
        btn.textContent = user.emp_id;
        btn.addEventListener('click', () => {
            select.value = user.emp_id;
            renderMainGraphExplorer(user.emp_id);
        });
        quickLinksContainer.appendChild(btn);
    });
}

async function renderMainGraphExplorer(empId) {
    const canvasContainer = document.getElementById('main-graph-canvas');
    const emptyState = document.getElementById('main-graph-empty-state');
    const inspector = document.getElementById('main-graph-inspector');
    const inspectorContent = document.getElementById('main-graph-inspector-content');
    
    // Clear old main vis instance
    if (state.mainVisNetwork) {
        state.mainVisNetwork.destroy();
        state.mainVisNetwork = null;
    }
    
    if (!empId) {
        emptyState.classList.remove('hidden');
        inspector.style.display = 'none';
        return;
    }
    
    emptyState.classList.add('hidden');
    
    // Create loading display
    const loader = document.createElement('div');
    loader.className = 'loading-overlay';
    loader.textContent = `Building entitlement mapping network for ${empId}...`;
    canvasContainer.appendChild(loader);
    
    const details = await apiFetch(`/api/identity/${empId}`);
    if (loader) loader.remove();
    
    if (!details || !details.graph || details.graph.nodes.length === 0) {
        canvasContainer.innerHTML = '<div class="empty-state">Failed to build entitlement graph for this user.</div>';
        return;
    }
    
    const graphData = details.graph;
    
    // Map raw data into Vis.js Nodes
    const visNodes = graphData.nodes.map(n => {
        let nodeColor = { background: '#1e293b', border: '#334155' };
        let nodeShape = 'box';
        let borderWidth = 1.5;
        
        if (n.type === 'identity') {
            nodeShape = 'ellipse';
            nodeColor = { background: '#2563eb', border: '#1d4ed8' };
            borderWidth = 2.5;
        } else if (n.type === 'account') {
            nodeShape = 'box';
            const borderCol = n.status === 'Active' ? '#10b981' : '#64748b';
            
            if (n.platform === 'AD') {
                nodeColor = { background: '#1e3a8a', border: borderCol };
            } else if (n.platform === 'AWS') {
                nodeColor = { background: '#7c2d12', border: borderCol };
            } else {
                nodeColor = { background: '#0f172a', border: borderCol };
            }
            borderWidth = 2;
        } else if (n.type === 'group') {
            nodeShape = 'hexagon';
            nodeColor = { background: '#5b21b6', border: '#7c3aed' };
        } else if (n.type === 'permission') {
            nodeShape = 'diamond';
            const isAdmin = n.label.toLowerCase().includes('admin');
            nodeColor = isAdmin 
                ? { background: '#7f1d1d', border: '#ef4444' }
                : { background: '#064e3b', border: '#34d399' };
        }
        
        return {
            id: n.id,
            label: n.label,
            shape: nodeShape,
            color: {
                background: nodeColor.background,
                border: nodeColor.border,
                highlight: {
                    background: '#4f46e5',
                    border: '#6366f1'
                }
            },
            borderWidth: borderWidth,
            font: {
                color: '#f8fafc',
                size: 11,
                face: 'Inter, system-ui'
            },
            margin: 10,
            rawData: n
        };
    });
    
    // Map edges
    const visEdges = graphData.edges.map(e => {
        let edgeColor = '#475569';
        let edgeDashes = false;
        
        if (e.type === 'entitlement') {
            edgeColor = '#f43f5e';
        } else if (e.type === 'mapping') {
            edgeColor = '#818cf8';
            edgeDashes = true;
        }
        
        return {
            from: e.from,
            to: e.to,
            color: edgeColor,
            arrows: {
                to: { enabled: true, scaleFactor: 0.8 }
            },
            dashes: edgeDashes,
            width: 1.5
        };
    });
    
    const visData = {
        nodes: new vis.DataSet(visNodes),
        edges: new vis.DataSet(visEdges)
    };
    
    const options = {
        nodes: {
            margin: 8,
            shadow: false
        },
        edges: {
            smooth: {
                type: 'cubicBezier',
                forceDirection: 'vertical',
                roundness: 0.4
            }
        },
        physics: {
            hierarchicalRepulsion: {
                nodeDistance: 130
            },
            stabilization: {
                iterations: 150
            }
        },
        layout: {
            hierarchical: {
                direction: 'UD',
                sortMethod: 'directed',
                nodeSpacing: 160,
                levelCalculationMethod: 'hubsize'
            }
        },
        interaction: {
            hover: true,
            zoomView: true,
            dragView: true
        }
    };
    
    state.mainVisNetwork = new vis.Network(canvasContainer, visData, options);
    
    inspector.style.display = 'block';
    inspectorContent.innerHTML = `
        <div style="margin-top:20px; text-align:center;" class="text-muted">
            <p class="text-sm">Graph loaded successfully for <strong>${empId}</strong>.</p>
            <p class="text-xs" style="margin-top:8px;">Click any node to inspect entitlement details.</p>
        </div>
    `;
    
    state.mainVisNetwork.once('stabilizationFinished', () => {
        state.mainVisNetwork.fit();
    });
    
    state.mainVisNetwork.on('click', (params) => {
        if (params.nodes && params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            const nodeData = visData.nodes.get(nodeId);
            const n = nodeData.rawData;
            
            let htmlContent = '';
            
            if (n.type === 'identity') {
                htmlContent = `
                    <div style="display:flex; flex-direction:column; gap:12px; margin-top:10px;">
                        <div>
                            <span class="text-muted text-xs uppercase" style="display:block; font-weight:600; font-size:10px;">Node Type</span>
                            <span class="badge badge-low" style="margin-top:4px;">HUMAN IDENTITY</span>
                        </div>
                        <div>
                            <span class="text-muted text-xs uppercase" style="display:block; font-weight:600; font-size:10px;">Employee ID</span>
                            <strong style="font-size:14px; color:var(--text-primary);">${n.id}</strong>
                        </div>
                        <div>
                            <span class="text-muted text-xs uppercase" style="display:block; font-weight:600; font-size:10px;">Job Title</span>
                            <span class="text-sm" style="display:block; margin-top:2px;">${n.title || 'N/A'}</span>
                        </div>
                        <div>
                            <span class="text-muted text-xs uppercase" style="display:block; font-weight:600; font-size:10px;">Department</span>
                            <span class="text-sm" style="display:block; margin-top:2px;">${n.department || 'N/A'}</span>
                        </div>
                        <div>
                            <span class="text-muted text-xs uppercase" style="display:block; font-weight:600; font-size:10px;">HR Employment Status</span>
                            <span class="badge ${n.status === 'Active' ? 'badge-active' : 'badge-disabled'}" style="margin-top:4px;">${n.status}</span>
                        </div>
                    </div>
                `;
            } else if (n.type === 'account') {
                htmlContent = `
                    <div style="display:flex; flex-direction:column; gap:12px; margin-top:10px;">
                        <div>
                            <span class="text-muted text-xs uppercase" style="display:block; font-weight:600; font-size:10px;">Node Type</span>
                            <span class="badge badge-medium" style="margin-top:4px;">PLATFORM ACCOUNT</span>
                        </div>
                        <div>
                            <span class="text-muted text-xs uppercase" style="display:block; font-weight:600; font-size:10px;">Account ID</span>
                            <strong style="font-size:12px; font-family:monospace; color:var(--text-primary); word-break:break-all;">${n.id}</strong>
                        </div>
                        <div>
                            <span class="text-muted text-xs uppercase" style="display:block; font-weight:600; font-size:10px;">Platform Provider</span>
                            <span class="text-sm" style="display:block; margin-top:2px; font-weight:500; color:var(--primary);">${n.platform}</span>
                        </div>
                        <div>
                            <span class="text-muted text-xs uppercase" style="display:block; font-weight:600; font-size:10px;">Account Status</span>
                            <span class="badge ${n.status === 'Active' ? 'badge-active' : 'badge-disabled'}" style="margin-top:4px;">${n.status}</span>
                        </div>
                    </div>
                `;
            } else if (n.type === 'group') {
                htmlContent = `
                    <div style="display:flex; flex-direction:column; gap:12px; margin-top:10px;">
                        <div>
                            <span class="text-muted text-xs uppercase" style="display:block; font-weight:600; font-size:10px;">Node Type</span>
                            <span class="badge badge-high" style="margin-top:4px;">GROUP / ROLE BINDING</span>
                        </div>
                        <div>
                            <span class="text-muted text-xs uppercase" style="display:block; font-weight:600; font-size:10px;">Group ID</span>
                            <strong style="font-size:12px; font-family:monospace; color:var(--text-primary);">${n.id}</strong>
                        </div>
                        <div>
                            <span class="text-muted text-xs uppercase" style="display:block; font-weight:600; font-size:10px;">Platform Context</span>
                            <span class="text-sm" style="display:block; margin-top:2px; font-weight:500;">${n.platform || 'N/A'}</span>
                        </div>
                    </div>
                `;
            } else if (n.type === 'permission') {
                const isAdmin = n.label.toLowerCase().includes('admin');
                htmlContent = `
                    <div style="display:flex; flex-direction:column; gap:12px; margin-top:10px;">
                        <div>
                            <span class="text-muted text-xs uppercase" style="display:block; font-weight:600; font-size:10px;">Node Type</span>
                            <span class="badge ${isAdmin ? 'badge-critical' : 'badge-active'}" style="margin-top:4px;">TERMINAL PERMISSION</span>
                        </div>
                        <div>
                            <span class="text-muted text-xs uppercase" style="display:block; font-weight:600; font-size:10px;">Entitlement Name</span>
                            <strong style="font-size:13px; color:var(--text-primary);">${n.id}</strong>
                        </div>
                        <div>
                            <span class="text-muted text-xs uppercase" style="display:block; font-weight:600; font-size:10px;">Permission Level</span>
                            <span class="text-sm ${isAdmin ? 'text-critical' : 'text-success'}" style="display:block; margin-top:2px; font-weight:600;">${isAdmin ? 'ADMINISTRATOR (HIGH RISK)' : 'STANDARD/USER'}</span>
                        </div>
                    </div>
                `;
            }
            inspectorContent.innerHTML = htmlContent;
        } else {
            inspectorContent.innerHTML = `
                <div style="margin-top:20px; text-align:center;" class="text-muted">
                    <p class="text-xs">Click any node to inspect entitlement details.</p>
                </div>
            `;
        }
    });
}
