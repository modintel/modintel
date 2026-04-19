async function generateDataset() {
    const attackType = document.getElementById('attack-type').value;
    const sampleCount = document.getElementById('sample-count').value;
    
    const btn = document.querySelector('.btn-primary');
    btn.textContent = 'Generating...';
    btn.disabled = true;
    
    setTimeout(() => {
        btn.textContent = 'Generated!';
        btn.disabled = false;
        setTimeout(() => btn.textContent = 'Generate', 2000);
    }, 2000);
}

const generateDatasetBtn = document.getElementById('generate-dataset-btn');
if (generateDatasetBtn) {
    generateDatasetBtn.addEventListener('click', generateDataset);
}
