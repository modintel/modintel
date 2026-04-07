import React from 'react';
import './CTA.css';

const CTA = () => {
    return (
        <section className="cta-section">
            <div className="container">
                <div className="cta-container">
                    <div className="cta-glow"></div>
                    <h2>Ready to Secure Your Infrastructure?</h2>
                    <p>
                        Reduce false positives and gain real-time visibility into your threats today.
                    </p>
                    <div className="cta-buttons">
                        <button className="btn-hero">Get Started Now</button>
                        <button className="btn-hero-secondary">Contact Sales</button>
                    </div>
                </div>
            </div>
        </section>
    );
};

export default CTA;
