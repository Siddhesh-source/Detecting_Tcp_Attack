import React from 'react';

export default function StoryBanner({ stories }) {
  if (!stories || stories.length === 0) return null;
  const latest = stories[0];
  return (
    <div className="story-banner">
      <span style={{ fontSize: '0.9rem', flexShrink: 0 }}>🚨</span>
      <span className="story-time">{latest.time}</span>
      <span className="story-text" dangerouslySetInnerHTML={{ __html: latest.text.replace(/score (\d+)/, 'score <strong>$1</strong>').replace(/→/, '<strong>→</strong>') }} />
    </div>
  );
}
