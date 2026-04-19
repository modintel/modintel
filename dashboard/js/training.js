const API_BASE = '/api';

document.getElementById('val-split').addEventListener('input', function() {
    document.getElementById('val-split-val').textContent = this.value + '%';
});

async function trainModel() {
    const dataset = document.getElementById('train-dataset').value;
    const modelType = document.getElementById('model-type').value;
    const valSplit = document.getElementById('val-split').value;
    
    const btn = document.querySelector('.btn-primary');
    btn.textContent = 'Training...';
    btn.disabled = true;
    
    setTimeout(() => {
        btn.textContent = 'Training Complete';
        btn.disabled = false;
        setTimeout(() => btn.textContent = 'Start Training', 2000);
    }, 3000);
}

const trainModelBtn = document.getElementById('train-model-btn');
if (trainModelBtn) {
    trainModelBtn.addEventListener('click', trainModel);
}
