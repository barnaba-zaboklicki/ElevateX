document.addEventListener("DOMContentLoaded", function () {
  // Select slider items and navigation buttons
  const items = document.querySelectorAll('.slider .list .item');
  const next = document.querySelector('.next');
  const prev = document.querySelector('.prev');

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
  })

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
});
