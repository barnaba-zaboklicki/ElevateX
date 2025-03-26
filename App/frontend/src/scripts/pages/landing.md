# Landing Page JavaScript Documentation

## Overview
The `landing.js` file handles the image slider functionality on the landing page, including slide transitions, thumbnail navigation, and content updates.

## Dependencies
- Swiper.js library for slider functionality
- Font Awesome for icons

## Key Components

### Swiper Initialization
```javascript
const swiper = new Swiper('.swiper', {
    effect: 'coverflow',
    grabCursor: true,
    centeredSlides: true,
    slidesPerView: 'auto',
    coverflowEffect: {
        rotate: 0,
        stretch: 0,
        depth: 100,
        modifier: 2,
        slideShadows: true,
    },
    pagination: {
        el: '.swiper-pagination',
        clickable: true,
    },
});
```

### Event Listeners
1. **Slide Change Event**
   - Updates the main slider content when a thumbnail is clicked
   - Handles the transition between slides
   - Updates active states and content display

2. **Navigation Buttons**
   - Previous button: Moves to the previous slide
   - Next button: Moves to the next slide
   - Includes visual feedback on hover

### Content Management
- Handles dynamic content updates for each slide
- Manages text animations and transitions
- Controls visibility of slide content

## Functions

### `updateSlider(index)`
Updates the main slider content based on the selected thumbnail.

**Parameters:**
- `index` (number): The index of the selected slide

**Functionality:**
- Updates the main image
- Updates the title and description
- Handles content transitions
- Manages active states

### `handleSlideChange()`
Handles the slide change event from the Swiper instance.

**Functionality:**
- Updates the main slider content
- Manages active states
- Handles content transitions

## Event Handlers

### Navigation Button Events
```javascript
prevBtn.addEventListener('click', () => {
    swiper.slidePrev();
});

nextBtn.addEventListener('click', () => {
    swiper.slideNext();
});
```

### Swiper Events
```javascript
swiper.on('slideChange', handleSlideChange);
```

## Usage
The script is automatically initialized when the page loads. It requires the following HTML structure:
- A main slider container with class `.slider`
- A list of slides with class `.list`
- Thumbnail navigation using Swiper
- Navigation buttons with classes `.prev` and `.next`

## Browser Support
- Modern browsers (Chrome, Firefox, Safari, Edge)
- IE11 and above

## Notes
- The slider uses CSS transitions for smooth animations
- Thumbnail navigation is synchronized with the main slider
- Content updates are handled dynamically
- Responsive design is supported through media queries 