/**
 * ZipLogsAnonymizer Treemap Visualization
 *
 * Uses D3.js to render a treemap showing file processing progress.
 * - Area represents file size
 * - Color represents category (large/small/binary) and status (queued/in_progress/done)
 */

// Global state
let treemapData = null;
let treemapRoot = null;
let fileStatuses = {};  // filename -> status
let containerWidth = 0;
let containerHeight = 0;

// Countdown timer state
let etaSeconds = null;
let countdownInterval = null;
let isProcessing = false;

// Status display names
const STATUS_NAMES = {
    'queued': 'Queued',
    'in_progress': 'In Progress',
    'done': 'Done'
};

/**
 * Initialize the treemap with file manifest data
 * Called from Python when a zip file is selected
 */
function initTreemap(manifest) {
    console.log('Initializing treemap with manifest:', manifest);

    // Reset state
    fileStatuses = {};
    isProcessing = false;
    stopCountdown();
    hideCompleteOverlay();

    // Build hierarchical data for D3
    const children = [];

    // Add large files as individual items
    if (manifest.largeFiles && manifest.largeFiles.length > 0) {
        manifest.largeFiles.forEach(file => {
            fileStatuses[file.name] = 'queued';
            children.push({
                name: file.name,
                displayName: truncateName(file.name, 40),
                size: file.size_mb,
                category: 'large',
                type: 'file'
            });
        });
    }

    // Add small files as grouped item
    if (manifest.smallFiles && manifest.smallFiles.total_mb > 0) {
        fileStatuses['__small_files__'] = 'queued';
        children.push({
            name: '__small_files__',
            displayName: `Small Files (${manifest.smallFiles.count} files)`,
            size: manifest.smallFiles.total_mb,
            category: 'small',
            type: 'group',
            count: manifest.smallFiles.count
        });
    }

    // Add binary files as grouped item
    if (manifest.binaryFiles && manifest.binaryFiles.total_mb > 0) {
        fileStatuses['__binary_files__'] = 'queued';
        children.push({
            name: '__binary_files__',
            displayName: `Binary/Other (${manifest.binaryFiles.count} files)`,
            size: manifest.binaryFiles.total_mb,
            category: 'binary',
            type: 'group',
            count: manifest.binaryFiles.count
        });
    }

    // Create hierarchical structure
    treemapData = {
        name: 'root',
        children: children
    };

    // Remove placeholder
    const placeholder = document.querySelector('.treemap-placeholder');
    if (placeholder) {
        placeholder.remove();
    }

    // Render the treemap
    renderTreemap();

    // Setup resize observer
    setupResizeObserver();
}

/**
 * Truncate filename for display
 */
function truncateName(name, maxLen) {
    if (name.length <= maxLen) return name;
    const ext = name.includes('.') ? name.split('.').pop() : '';
    const baseName = name.substring(0, name.length - ext.length - 1);
    const truncatedBase = baseName.substring(0, maxLen - ext.length - 4) + '...';
    return truncatedBase + '.' + ext;
}

/**
 * Create the appropriate icon element for a status
 */
function createIconElement(status) {
    const icon = document.createElement('span');
    icon.className = 'treemap-cell-icon';

    if (status === 'queued') {
        icon.classList.add('icon-queued');
        // Animated ellipsis handled by CSS
    } else if (status === 'in_progress') {
        icon.classList.add('icon-in-progress');
        // Spinning circle handled by CSS
    } else if (status === 'done') {
        icon.classList.add('icon-done');
        // Checkmark handled by CSS
    }

    return icon;
}

/**
 * Render or re-render the treemap
 */
function renderTreemap() {
    if (!treemapData || !treemapData.children || treemapData.children.length === 0) {
        return;
    }

    const container = document.getElementById('treemap-container');
    containerWidth = container.clientWidth;
    containerHeight = container.clientHeight;

    if (containerWidth === 0 || containerHeight === 0) {
        return;
    }

    // Clear existing cells (but keep the overlay)
    const existingCells = container.querySelectorAll('.treemap-cell');
    existingCells.forEach(cell => cell.remove());

    // Create D3 hierarchy
    treemapRoot = d3.hierarchy(treemapData)
        .sum(d => d.size)
        .sort((a, b) => b.value - a.value);

    // Create treemap layout
    d3.treemap()
        .size([containerWidth, containerHeight])
        .padding(2)
        .round(true)(treemapRoot);

    // Create cells
    treemapRoot.leaves().forEach(node => {
        const data = node.data;
        const status = fileStatuses[data.name] || 'queued';

        // Create cell element
        const cell = document.createElement('div');
        cell.className = `treemap-cell cell-${data.category} status-${status}`;
        cell.dataset.name = data.name;
        cell.style.left = `${node.x0}px`;
        cell.style.top = `${node.y0}px`;
        cell.style.width = `${node.x1 - node.x0}px`;
        cell.style.height = `${node.y1 - node.y0}px`;

        // Check if cell is too small for labels
        const cellWidth = node.x1 - node.x0;
        const cellHeight = node.y1 - node.y0;
        if (cellWidth < 60 || cellHeight < 40) {
            cell.classList.add('small-cell');
        }

        // Create content
        const content = document.createElement('div');
        content.className = 'treemap-cell-content';

        // Label with animated icon
        const label = document.createElement('div');
        label.className = 'treemap-cell-label';
        const icon = createIconElement(status);
        label.appendChild(icon);
        label.appendChild(document.createTextNode(data.displayName));
        content.appendChild(label);

        // Size
        const sizeLabel = document.createElement('div');
        sizeLabel.className = 'treemap-cell-size';
        sizeLabel.textContent = formatSize(data.size);
        content.appendChild(sizeLabel);

        cell.appendChild(content);

        // Tooltip events - pass data.name so we can look up current status
        cell.addEventListener('mouseenter', (e) => showTooltip(e, data));
        cell.addEventListener('mousemove', (e) => moveTooltip(e));
        cell.addEventListener('mouseleave', hideTooltip);

        container.appendChild(cell);
    });
}

/**
 * Update the status of a file
 * Called from Python during processing
 */
function updateFileStatus(name, status) {
    console.log('Updating file status:', name, status);

    fileStatuses[name] = status;

    // Find and update the cell
    const cell = document.querySelector(`.treemap-cell[data-name="${CSS.escape(name)}"]`);
    if (cell) {
        // Update status class
        cell.classList.remove('status-queued', 'status-in_progress', 'status-done');
        cell.classList.add(`status-${status}`);

        // Update icon with new animated version
        const oldIcon = cell.querySelector('.treemap-cell-icon');
        if (oldIcon) {
            const newIcon = createIconElement(status);
            oldIcon.parentNode.replaceChild(newIcon, oldIcon);
        }
    }
}

/**
 * Update the status of a group (small_files or binary_files)
 * Called from Python during processing
 */
function updateGroupStatus(groupType, status) {
    const name = `__${groupType}__`;
    updateFileStatus(name, status);
}

/**
 * Start the countdown timer
 */
function startCountdown() {
    if (countdownInterval) return; // Already running

    isProcessing = true;
    countdownInterval = setInterval(() => {
        if (etaSeconds !== null && etaSeconds > 0) {
            etaSeconds = Math.max(0, etaSeconds - 1);
            document.getElementById('stat-eta').textContent = formatEta(etaSeconds);
        }
    }, 1000);
}

/**
 * Stop the countdown timer
 */
function stopCountdown() {
    if (countdownInterval) {
        clearInterval(countdownInterval);
        countdownInterval = null;
    }
    isProcessing = false;
}

/**
 * Update stats display
 * Called from Python during processing
 */
function updateStats(stats) {
    if (stats.progress_pct !== undefined) {
        document.getElementById('stat-progress').textContent = `${Math.round(stats.progress_pct)}%`;
    }
    if (stats.total_mb !== undefined) {
        document.getElementById('stat-total-size').textContent = formatSize(stats.total_mb);
    }
    if (stats.throughput_mbs !== undefined) {
        document.getElementById('stat-throughput').textContent = `${stats.throughput_mbs.toFixed(2)} MB/s`;
    }
    if (stats.eta_seconds !== undefined && stats.eta_seconds !== null) {
        // Update the ETA and restart countdown from this value
        etaSeconds = stats.eta_seconds;
        document.getElementById('stat-eta').textContent = formatEta(etaSeconds);
        // Start countdown if not already running
        if (!countdownInterval && isProcessing) {
            startCountdown();
        }
    }
}

/**
 * Reset stats display
 */
function resetStats() {
    document.getElementById('stat-progress').textContent = '--';
    document.getElementById('stat-total-size').textContent = '--';
    document.getElementById('stat-throughput').textContent = '--';
    document.getElementById('stat-eta').textContent = '--';
    etaSeconds = null;
    stopCountdown();
}

/**
 * Set the file path display
 */
function setFilePath(path) {
    document.getElementById('file-path').value = path;
}

/**
 * Update button states
 */
function setButtonState(buttonId, enabled) {
    const btn = document.getElementById(buttonId);
    if (btn) {
        btn.disabled = !enabled;
    }
}

/**
 * Update status text
 */
function setStatus(text) {
    document.getElementById('status-text').textContent = text;
}

/**
 * Clear the treemap
 */
function clearTreemap() {
    treemapData = null;
    treemapRoot = null;
    fileStatuses = {};
    stopCountdown();
    hideCompleteOverlay();

    const container = document.getElementById('treemap-container');
    // Remove all cells but keep the overlay
    const cells = container.querySelectorAll('.treemap-cell');
    cells.forEach(cell => cell.remove());

    // Add placeholder back
    const placeholder = document.createElement('div');
    placeholder.className = 'treemap-placeholder';
    placeholder.innerHTML = '<p>Select a zip file to visualize processing progress</p>';
    container.insertBefore(placeholder, container.firstChild);
}

/**
 * Show the complete overlay
 */
function showCompleteOverlay() {
    // Hide any visible tooltip first
    hideTooltip();

    const overlay = document.getElementById('complete-overlay');
    const container = document.getElementById('treemap-container');
    if (overlay) {
        overlay.classList.add('visible');
    }
    if (container) {
        container.classList.add('completed');
    }
}

/**
 * Hide the complete overlay
 */
function hideCompleteOverlay() {
    const overlay = document.getElementById('complete-overlay');
    const container = document.getElementById('treemap-container');
    if (overlay) {
        overlay.classList.remove('visible');
    }
    if (container) {
        container.classList.remove('completed');
    }
}

/**
 * Format size in MB/GB
 */
function formatSize(sizeMb) {
    if (sizeMb >= 1000) {
        return `${(sizeMb / 1024).toFixed(2)} GB`;
    }
    return `${sizeMb.toFixed(1)} MB`;
}

/**
 * Format ETA in human readable format
 */
function formatEta(seconds) {
    if (seconds === null || seconds === undefined || seconds < 0) {
        return '--';
    }
    if (seconds < 60) {
        return `${Math.round(seconds)}s`;
    }
    if (seconds < 3600) {
        const mins = Math.floor(seconds / 60);
        const secs = Math.round(seconds % 60);
        return `${mins}m ${secs}s`;
    }
    const hours = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    return `${hours}h ${mins}m`;
}

/**
 * Show tooltip - reads current status from fileStatuses
 */
function showTooltip(event, data) {
    const tooltip = document.getElementById('tooltip');

    // Get CURRENT status from fileStatuses, not the captured value
    const status = fileStatuses[data.name] || 'queued';

    let html = `<div class="tooltip-title">${data.name === '__small_files__' ? 'Small Files' : data.name === '__binary_files__' ? 'Binary/Other Files' : data.name}</div>`;

    if (data.type === 'group') {
        html += `<div class="tooltip-row"><span class="tooltip-label">Files:</span><span class="tooltip-value">${data.count}</span></div>`;
    }
    html += `<div class="tooltip-row"><span class="tooltip-label">Size:</span><span class="tooltip-value">${formatSize(data.size)}</span></div>`;
    html += `<div class="tooltip-row"><span class="tooltip-label">Status:</span><span class="tooltip-value tooltip-status-${status}">${STATUS_NAMES[status]}</span></div>`;

    tooltip.innerHTML = html;
    tooltip.classList.add('visible');

    moveTooltip(event);
}

/**
 * Move tooltip to follow cursor
 */
function moveTooltip(event) {
    const tooltip = document.getElementById('tooltip');
    const container = document.querySelector('.treemap-section');
    const containerRect = container.getBoundingClientRect();

    let x = event.clientX - containerRect.left + 15;
    let y = event.clientY - containerRect.top + 15;

    // Keep tooltip in bounds
    const tooltipRect = tooltip.getBoundingClientRect();
    if (x + tooltipRect.width > containerRect.width) {
        x = event.clientX - containerRect.left - tooltipRect.width - 15;
    }
    if (y + tooltipRect.height > containerRect.height) {
        y = event.clientY - containerRect.top - tooltipRect.height - 15;
    }

    tooltip.style.left = `${x}px`;
    tooltip.style.top = `${y}px`;
}

/**
 * Hide tooltip
 */
function hideTooltip() {
    const tooltip = document.getElementById('tooltip');
    tooltip.classList.remove('visible');
}

/**
 * Setup resize observer to re-render on window resize
 */
function setupResizeObserver() {
    const container = document.getElementById('treemap-container');

    const resizeObserver = new ResizeObserver(entries => {
        for (let entry of entries) {
            const newWidth = entry.contentRect.width;
            const newHeight = entry.contentRect.height;

            // Only re-render if size actually changed
            if (newWidth !== containerWidth || newHeight !== containerHeight) {
                renderTreemap();
            }
        }
    });

    resizeObserver.observe(container);
}

/**
 * Get checkbox values (called from Python)
 */
function getOptions() {
    return {
        createZip: document.getElementById('create-zip').checked,
        keepUncompressed: document.getElementById('keep-uncompressed').checked
    };
}

/**
 * Called when processing starts
 */
function processingStarted() {
    isProcessing = true;
    hideCompleteOverlay();
    hideOutputInfo();

    // Add processing class to enable animations
    const container = document.getElementById('treemap-container');
    if (container) {
        container.classList.add('processing');
    }

    // Hide status spinner initially
    const spinner = document.getElementById('status-spinner');
    if (spinner) {
        spinner.classList.add('hidden');
    }
}

/**
 * Show the creating zip status
 */
function showCreatingZip() {
    setStatus('Creating output zip file...');
    const spinner = document.getElementById('status-spinner');
    if (spinner) {
        spinner.classList.remove('hidden');
    }
}

/**
 * Hide the status spinner
 */
function hideStatusSpinner() {
    const spinner = document.getElementById('status-spinner');
    if (spinner) {
        spinner.classList.add('hidden');
    }
}

/**
 * Show the output info section with the path
 */
function showOutputInfo(outputPath, outputZipPath) {
    const outputInfo = document.getElementById('output-info');
    const outputPathEl = document.getElementById('output-path');

    if (outputInfo && outputPathEl) {
        // Determine what to show
        let displayPath = '';
        if (outputZipPath) {
            displayPath = outputZipPath;
        } else if (outputPath) {
            displayPath = outputPath;
        }

        if (displayPath) {
            outputPathEl.textContent = displayPath;
            outputPathEl.title = `Click to open: ${displayPath}`;
            outputPathEl.onclick = () => pywebview.api.open_output_folder();
            outputInfo.classList.remove('hidden');
        }
    }
}

/**
 * Hide the output info section
 */
function hideOutputInfo() {
    const outputInfo = document.getElementById('output-info');
    if (outputInfo) {
        outputInfo.classList.add('hidden');
    }
}

/**
 * Mark processing as complete
 */
function processingComplete(success, outputPath, outputZipPath) {
    console.log('Processing complete, success:', success, 'outputPath:', outputPath, 'outputZipPath:', outputZipPath);
    stopCountdown();
    isProcessing = false;
    hideStatusSpinner();
    hideTooltip();

    // Remove processing class
    const container = document.getElementById('treemap-container');
    if (container) {
        container.classList.remove('processing');
    }

    if (success) {
        updateStats({ progress_pct: 100 });
        document.getElementById('stat-eta').textContent = 'Done!';
        showCompleteOverlay();

        // Show output info
        if (outputPath || outputZipPath) {
            showOutputInfo(outputPath, outputZipPath);
        }
    }
}

// Enable UI only after BOTH pywebview API and all page resources are ready
(function() {
    let apiReady = false;
    let pageLoaded = false;

    function tryEnable() {
        if (apiReady && pageLoaded) {
            document.getElementById('browse-btn').disabled = false;
        }
    }

    window.addEventListener('pywebviewready', () => {
        apiReady = true;
        tryEnable();
    });

    window.addEventListener('load', () => {
        pageLoaded = true;
        tryEnable();
    });

    // If pywebview API is already available (e.g. events fired before script ran)
    if (window.pywebview && window.pywebview.api) {
        apiReady = true;
        tryEnable();
    }
    if (document.readyState === 'complete') {
        pageLoaded = true;
        tryEnable();
    }
})();
