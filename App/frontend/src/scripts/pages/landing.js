document.addEventListener("DOMContentLoaded", function () {
  // Select slider items and navigation buttons
  const items = document.querySelectorAll('.slider .list .item');
  const next = document.querySelector('.next');
  const prev = document.querySelector('.prev');
  const slider = document.querySelector('.slider');
  const loginWrapper = document.querySelector('.login-wrapper');
  const registerWrapper = document.querySelector('.register-wrapper');
  const showRegisterBtn = document.getElementById('show-register');
  const showLoginBtn = document.getElementById('show-login');
  const thumbnailSlider = document.querySelector('.swiper');

  let itemActive = 0;

  // Initialize Swiper.js
  var swiper = new Swiper(".swiper", {
    effect: "coverflow",
    grabCursor: true,
    centeredSlides: true,
    initialSlide: "0",
    speed: 600,
    allowTouchMove: true,
    autoplay: {
      delay: 5000,
      disableOnInteraction: true,
    },
    preventClicks: true,
    slidesPerView: "auto",
    coverflowEffect: {
      rotate: -8,
      stretch: -10,
      depth: 30,
      modifier: 2,
      slideShadows: true,
    },
    on: {
      click(event) {
        swiper.slideTo(this.clickedIndex);
      },
    },
    pagination: {
      el: ".swiper-pagination",
    },
    loop: true,
    navigation: {
      nextEl: ".next",
      prevEl: ".prev",
    },
  });

  function updateMainSlider(index) {
    // Remove active class from previous slider items
    document.querySelectorAll('.slider .list .item.active').forEach(el => el.classList.remove('active'));

    // Set new active item
    if (items[index]) {
      items[index].classList.add('active');
    }
  }

  // Sync Swiper with Main Slider
  swiper.on('slideChange', function () {
    itemActive = swiper.realIndex;
    updateMainSlider(itemActive);
  });

  // Handle showing registration form
  showRegisterBtn.addEventListener('click', function(e) {
    e.preventDefault();
    console.log('Showing registration form');
    
    if (thumbnailSlider) {
      console.log('Found thumbnail slider, hiding it');
      thumbnailSlider.style.display = 'none';
    } else {
      console.log('Thumbnail slider not found');
    }
    
    loginWrapper.style.display = 'none';
    registerWrapper.classList.add('active');
  });

  // Handle showing login form
  showLoginBtn.addEventListener('click', function(e) {
    e.preventDefault();
    console.log('Showing login form');
    
    if (thumbnailSlider) {
      console.log('Found thumbnail slider, showing it');
      thumbnailSlider.style.display = 'block';
    } else {
      console.log('Thumbnail slider not found');
    }
    
    registerWrapper.classList.remove('active');
    loginWrapper.style.display = 'block';
  });
});
