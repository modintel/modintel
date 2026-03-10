const fs = require('fs');
const pdf = require('pdf-parse');

async function extract() {
    try {
        let srsBuffer = fs.readFileSync('../docs/SRS.pdf');
        let srsData = await pdf(srsBuffer);
        fs.writeFileSync('../docs/SRS.txt', srsData.text);
        console.log('Extracted SRS.pdf');
        
        let sdsBuffer = fs.readFileSync('../docs/SDS.pdf');
        let sdsData = await pdf(sdsBuffer);
        fs.writeFileSync('../docs/SDS.txt', sdsData.text);
        console.log('Extracted SDS.pdf');
    } catch(e) {
        console.error(e);
    }
}
extract();
