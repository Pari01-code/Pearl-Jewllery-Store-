// script.js
// Handles fetching products, rendering, filters, cart & wishlist, checkout redirect.
// Local fallback products (from product.js)
const fallbackProducts = [
// Necklaces
{ id: 1, name: "Ruby Artificial Necklace Set", desc: "Elegant silver necklace with ruby stones.", price: 9500, category: "necklace", material: "artificial", img: "images/ad-1.jpg" },
{ id: 2, name: "Bridal Artificial Necklace Set", desc: "Heavy bridal necklace with red stones.", price: 12000, category: "necklace", material: "artificial", img: "images/ad-2.jpg" },
{ id: 3, name: "Black Stone Artificial Necklace", desc: "Designer necklace with black stones.", price: 11000, category: "necklace", material: "artificial", img: "images/ad-3.jpg" },

// Earrings
{ id: 4, name: "Artificial Diamond Wheel Earrings", desc: "Unique diamond-cut circular earrings.", price: 4500, category: "earring", material: "artificial", img: "images/ad-earing-1.jpg" },
{ id: 5, name: "Floral Artificial Diamond Earrings", desc: "Floral swirl diamond earrings.", price: 4800, category: "earring", material: "artificial", img: "images/ad-earing-2.jpg" },
{ id: 6, name: "Dual Circle Artificial Earrings", desc: "Trendy double-hoop stone earrings.", price: 5000, category: "earring", material: "artificial", img: "images/ad-earing-3.jpg" },

// Bracelets
{ id: 7, name: "Minimal Gold Bracelet", desc: "Simple slim gold bracelet.", price: 6500, category: "bracelet", material: "gold", img: "images/gold-bracelet-1.jpg" },
{ id: 8, name: "Twist Gold Bracelet", desc: "Stylish twisted rope gold bracelet.", price: 7200, category: "bracelet", material: "gold", img: "images/gold-bracelet-2.jpg" },

// Gold Chains
{ id: 9, name: "Classic Gold Chain", desc: "Elegant and simple gold chain.", price: 15000, category: "chain", material: "gold", img: "images/gold-chain-1.jpg" },
{ id: 10, name: "Textured Gold Chain", desc: "Stylish textured gold chain for daily wear.", price: 17000, category: "chain", material: "gold", img: "images/gold-chain-2.jpg" },
{ id: 11, name: "Heart Pendant Gold Chain", desc: "Gold chain with a heart pendant.", price: 18500, category: "chain", material: "gold", img: "images/gold-chain-3.jpg" },

// Gold Earrings
{ id: 12, name: "Floral Red Gold Earrings", desc: "Flower-inspired earrings with red accents.", price: 8000, category: "earring", material: "gold", img: "images/gold-earring-1.jpg" },
{ id: 13, name: "Round Gold Stud Earrings", desc: "Traditional round stud design in gold.", price: 7500, category: "earring", material: "gold", img: "images/gold-earring-2.jpg" },
{ id: 14, name: "Stone-studded Gold Earrings", desc: "Gold earrings with white stones.", price: 9500, category: "earring", material: "gold", img: "images/gold-earring-3.jpg" },

// Gold Mangalsutras
{ id: 15, name: "Traditional Gold Mangalsutra", desc: "Classic black bead mangalsutra with pendant.", price: 22000, category: "mangalsutra", material: "gold", img: "images/gold-mangalsutra-1.jpg" },
{ id: 16, name: "Designer Gold Mangalsutra", desc: "Designer pendant gold mangalsutra.", price: 25000, category: "mangalsutra", material: "gold", img: "images/gold-mangalsutra-2.jpg" },
{ id: 17, name: "Twin Pendant Gold Mangalsutra", desc: "Elegant twin pendant black bead mangalsutra.", price: 24000, category: "mangalsutra", material: "gold", img: "images/gold-mangalsutra-3.jpg" },

// Gold Rings
{ id: 18, name: "Eternity Gold Diamond Ring", desc: "Classic gold band with a row of diamonds.", price: 12500, category: "ring", material: "gold", img: "images/goldr-1.jpg" },
{ id: 19, name: "Solitaire Gold Diamond Ring", desc: "Stunning solitaire diamond on a stone-studded gold band.", price: 14000, category: "ring", material: "gold", img: "images/goldr-2.jpg" },
{ id: 20, name: "Wavy Gold Band Ring", desc: "Modern multi-layered wavy gold ring.", price: 8500, category: "ring", material: "gold", img: "images/goldr-3.jpg" },
{ id: 21, name: "Infinity Knot Gold Diamond Ring", desc: "Delicate gold ring with a diamond-studded infinity knot.", price: 9800, category: "ring", material: "gold", img: "images/goldr-4.jpg" },

// Artificial Mangalsutras
{ id: 22, name: "AD Mangalsutra Set", desc: "Curved AD pendant mangalsutra with matching earrings.", price: 10500, category: "mangalsutra", material: "artificial", img: "images/mangalsutra-ad-1.jpg" },
{ id: 23, name: "Halo AD Mangalsutra", desc: "Five halo-design AD stone pendant mangalsutra.", price: 11500, category: "mangalsutra", material: "artificial", img: "images/mangalsutra-ad-2.jpg" },
{ id: 24, name: "Floral AD Mangalsutra Set", desc: "Intricate floral AD pendant mangalsutra with flower earrings.", price: 12500, category: "mangalsutra", material: "artificial", img: "images/mangalsutra-ad-3.jpg" },

// Rose Gold Rings
{ id: 25, name: "Square Halo Rose Gold Ring", desc: "Elegant rose gold ring with a square halo diamond setting.", price: 13500, category: "ring", material: "rose gold", img: "images/rose-gold-ring-1.jpg" },
{ id: 26, name: "Bridal Rose Gold Ring Set", desc: "Stunning bridal set with a large solitaire and matching band.", price: 16000, category: "ring", material: "rose gold", img: "images/rose-gold-ring-2.jpg" },
{ id: 27, name: "Cushion Cut Rose Gold Ring Set", desc: "Beautiful cushion cut halo diamond ring with a matching band.", price: 15500, category: "ring", material: "rose gold", img: "images/rose-gold-ring-3.jpg" },
{ id: 28, name: "Criss-Cross Rose Gold Ring", desc: "Modern criss-cross design rose gold ring with pavé diamonds.", price: 11000, category: "ring", material: "rose gold", img: "images/rose-gold-ring-4.jpg" },

// Rose Gold & Silver Bracelets
{ id: 29, name: "Dainty Rose Gold Bracelet", desc: "Delicate and adjustable rose gold bracelet with a studded bar.", price: 6800, category: "bracelet", material: "rose gold", img: "images/rose-gold-bracelet-1.jpg" },
{ id: 30, name: "Engraved Rose Gold Bangle", desc: "Chic rose gold bangle with an engraved pattern and stone.", price: 7500, category: "bracelet", material: "rose gold", img: "images/rose-gold-bracelet-2.jpg" },
{ id: 31, name: "Rose Gold Charm Bracelet", desc: "Playful rose gold charm bracelet with an adjustable clasp.", price: 8200, category: "bracelet", material: "rose gold", img: "images/rose-gold-bracelet-3.jpg" },
{ id: 32, name: "Infinity Silver Bracelet", desc: "Elegant silver chain bracelet with a studded infinity symbol.", price: 5500, category: "bracelet", material: "silver", img: "images/silver-bracelet-1.jpg" },
{ id: 33, name: "Classic Silver Bangle", desc: "A timeless and sleek silver bangle with a studded center.", price: 6200, category: "bracelet", material: "silver", img: "images/silver-bracelet-2.jpg" },

// Silver Rings & Chains
{ id: 34, name: "Classic Solitaire Silver Ring", desc: "Timeless silver solitaire ring with a stone-studded band.", price: 9500, category: "ring", material: "silver", img: "images/silver-ring-1.jpg" },
{ id: 35, name: "Wide Filigree Silver Ring", desc: "An intricate, wide silver band with a beautiful filigree design.", price: 10500, category: "ring", material: "silver", img: "images/silver-ring-2.jpg" },
{ id: 36, name: "Dainty Silver Eternity Band", desc: "A delicate and simple silver eternity band for everyday wear.", price: 7200, category: "ring", material: "silver", img: "images/silver-ring-3.jpg" },
{ id: 37, name: "Chevron Silver Ring", desc: "Stylish V-shaped silver chevron ring, perfect for stacking.", price: 7800, category: "ring", material: "silver", img: "images/silver-ring-4.jpg" },
{ id: 38, name: "Sleek Silver Box Chain", desc: "A minimal and sleek silver box chain for a delicate look.", price: 6500, category: "chain", material: "silver", img: "images/silver-chain-1.jpg" },
{ id: 39, name: "Men's Flat Silver Chain", desc: "A bold and modern flat snake chain in pure silver for men.", price: 9200, category: "chain", material: "silver", img: "images/silver-chain-2.jpg" },
{ id: 40, name: "Classic Men's Silver Chain", desc: "A versatile and classic silver chain suitable for any occasion.", price: 8800, category: "chain", material: "silver", img: "images/silver-chain-3.jpg" }
];
let allProducts = [];
let filteredProducts = [];
let cart = JSON.parse(localStorage.getItem('cart')) || [];
let wishlist = JSON.parse(localStorage.getItem('wishlist')) || [];

document.addEventListener('DOMContentLoaded', () => {
  const productsContainer = document.querySelector(".products");
  const searchInput = document.getElementById('search-input');

  // Fetch products from backend with fallback
  fetch('/api/products')
    .then(res => res.json())
    .then(data => {
      if (data && data.success && Array.isArray(data.products) && data.products.length > 0) {
        allProducts = data.products;
      } else {
        console.warn('⚠️ No products in DB — using fallback products from script.js');
        allProducts = fallbackProducts;
      }
      filteredProducts = allProducts.slice();
      renderProducts(filteredProducts);
      updateCounts();
    })
    .catch(err => {
      console.error('❌ Error fetching products:', err);
      console.warn('➡️ Using fallback products from script.js');
      allProducts = fallbackProducts;
      filteredProducts = allProducts.slice();
      renderProducts(filteredProducts);
      updateCounts();
    });

  // Event delegation for cart & wishlist
  productsContainer.addEventListener('click', (e) => {
    const target = e.target;
    const id = target.dataset?.id && Number(target.dataset.id);
    if (!id) return;

    if (target.classList.contains('add-to-cart')) {
      addToCart(id);
    } else if (target.classList.contains('add-to-wishlist')) {
      toggleWishlist(id);
    }
  });

  // Search
  searchInput.addEventListener('input', () => applyFilters());
});

// ---------- Rendering ----------
function renderProducts(products) {
  const container = document.querySelector('.products');
  container.innerHTML = '';

  if (!products.length) {
    container.innerHTML = '<p style="padding:2rem;">No products found.</p>';
    return;
  }

  products.forEach(product => {
    const card = document.createElement('div');
    card.className = 'product-card';
    card.innerHTML = `
      <img src="${product.img}" alt="${escapeHtml(product.name)}" onerror="this.src='images/placeholder.png'">
      <h3>${escapeHtml(product.name)}</h3>
      <p>${escapeHtml(product.desc || '')}</p>
      <p>₹${Number(product.price).toLocaleString()}</p>
      <div style="display:flex;gap:.5rem;padding:0 1rem 1rem;">
        <button class="add-to-cart" data-id="${product.id}">Add to Cart</button>
        <button class="add-to-wishlist" data-id="${product.id}" title="Add to wishlist">♡</button>
      </div>
    `;
    container.appendChild(card);
  });
}

// ---------- Helpers ----------
function escapeHtml(text = '') {
  return String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// ---------- Filters ----------
function applyFilters() {
  const type = document.getElementById('filter-type').value;
  const material = document.getElementById('filter-material').value;
  const sort = document.getElementById('sort-price').value;
  const search = document.getElementById('search-input').value.trim().toLowerCase();

  filteredProducts = allProducts.filter(p => {
    if (type !== 'all' && p.category && p.category.toLowerCase() !== type.toLowerCase()) return false;
    if (material !== 'all' && p.material && p.material.toLowerCase() !== material.toLowerCase()) return false;
    if (search) {
      const hay = `${p.name} ${p.desc} ${p.category} ${p.material}`.toLowerCase();
      if (!hay.includes(search)) return false;
    }
    return true;
  });

  if (sort === 'low') {
    filteredProducts.sort((a, b) => a.price - b.price);
  } else if (sort === 'high') {
    filteredProducts.sort((a, b) => b.price - a.price);
  }

  renderProducts(filteredProducts);
}

function resetFilters() {
  document.getElementById('filter-type').value = 'all';
  document.getElementById('filter-material').value = 'all';
  document.getElementById('sort-price').value = 'default';
  document.getElementById('search-input').value = '';
  filteredProducts = allProducts.slice();
  renderProducts(filteredProducts);
}

// ---------- Cart & Wishlist ----------
function addToCart(productId) {
  const product = allProducts.find(p => Number(p.id) === Number(productId));
  if (!product) { alert('Product not found'); return; }

  const existing = cart.find(i => i.id === product.id);
  if (existing) {
    existing.qty += 1;
  } else {
    cart.push({ id: product.id, name: product.name, price: product.price, qty: 1, img: product.img });
  }
  localStorage.setItem('cart', JSON.stringify(cart));
  updateCounts();
  alert('Added to cart');
}

function removeFromCart(productId) {
  cart = cart.filter(i => i.id !== Number(productId));
  localStorage.setItem('cart', JSON.stringify(cart));
  renderCartModal();
  updateCounts();
}

function changeQty(productId, delta) {
  const item = cart.find(i => i.id === Number(productId));
  if (!item) return;
  item.qty = Math.max(1, item.qty + delta);
  localStorage.setItem('cart', JSON.stringify(cart));
  renderCartModal();
  updateCounts();
}

function toggleWishlist(productId) {
  productId = Number(productId);
  const idx = wishlist.findIndex(i => i.id === productId);
  if (idx >= 0) {
    wishlist.splice(idx, 1);
    alert('Removed from wishlist');
  } else {
    const p = allProducts.find(x => Number(x.id) === productId);
    if (!p) return alert('Product not found');
    wishlist.push({ id: p.id, name: p.name, price: p.price, img: p.img });
    alert('Added to wishlist');
  }
  localStorage.setItem('wishlist', JSON.stringify(wishlist));
  updateCounts();
  renderWishlistModal();
}

function updateCounts() {
  document.getElementById('cart-count').innerText = cart.reduce((s, i) => s + (i.qty || 0), 0);
  document.getElementById('wishlist-count').innerText = wishlist.length;
}

// ---------- Modals ----------
function toggleModal(id) {
  const modal = document.getElementById(id);
  if (!modal) return;
  const open = modal.classList.toggle('open');
  modal.setAttribute('aria-hidden', (!open).toString());

  if (id === 'cart-modal' && open) renderCartModal();
  if (id === 'wishlist-modal' && open) renderWishlistModal();
}

function renderCartModal() {
  const container = document.getElementById('cart-items');
  container.innerHTML = '';
  if (!cart.length) {
    container.innerHTML = '<p>Your cart is empty.</p>';
    document.getElementById('cart-total').innerText = '';
    return;
  }

  let total = 0;
  const table = document.createElement('table');
  table.innerHTML = `<thead><tr><th>Item</th><th>Qty</th><th>Price</th><th></th></tr></thead>`;
  const tbody = document.createElement('tbody');

  cart.forEach(item => {
    total += item.price * item.qty;
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="max-width:180px;">
        <div style="display:flex;gap:.5rem;align-items:center;">
          <img src="${item.img}" style="width:48px;height:48px;object-fit:cover;border-radius:6px;" onerror="this.src='images/placeholder.png'">
          <div>${escapeHtml(item.name)}</div>
        </div>
      </td>
      <td>
        <button onclick="changeQty(${item.id}, -1)">-</button>
        <span style="margin:0 .5rem">${item.qty}</span>
        <button onclick="changeQty(${item.id}, 1)">+</button>
      </td>
      <td>₹${(item.price * item.qty).toLocaleString()}</td>
      <td><button onclick="removeFromCart(${item.id})">Remove</button></td>
    `;
    tbody.appendChild(tr);
  });

  table.appendChild(tbody);
  container.appendChild(table);
  document.getElementById('cart-total').innerText = `Total: ₹${total.toLocaleString()}`;
}

function renderWishlistModal() {
  const container = document.getElementById('wishlist-items');
  container.innerHTML = '';

  if (!wishlist.length) {
    container.innerHTML = '<p>Your wishlist is empty.</p>';
    return;
  }

  wishlist.forEach(item => {
    const div = document.createElement('div');
    div.style.display = 'flex';
    div.style.gap = '.5rem';
    div.style.alignItems = 'center';
    div.style.marginBottom = '.75rem';
    div.innerHTML = `
      <img src="${item.img}" style="width:48px;height:48px;object-fit:cover;border-radius:6px;" onerror="this.src='images/placeholder.png'">
      <div style="flex:1">
        <div>${escapeHtml(item.name)}</div>
        <div>₹${Number(item.price).toLocaleString()}</div>
      </div>
      <div>
        <button onclick="addToCart(${item.id}); toggleWishlist(${item.id});">Add to Cart</button>
      </div>
    `;
    container.appendChild(div);
  });
}

// ---------- Checkout redirect ----------
function goToCheckout() {
  if (!cart.length) {
    alert('Your cart is empty.');
    return;
  }
  localStorage.setItem('checkoutCart', JSON.stringify(cart));
  window.location.href = 'checkout.html';
}

// ---------- Misc ----------
function scrollToProducts() {
  const el = document.getElementById('products');
  if (el) el.scrollIntoView({ behavior: 'smooth' });
}

updateCounts();

// ---------- Proceed to Payment ----------
document.addEventListener('DOMContentLoaded', () => {
  const proceedBtn = document.getElementById('proceed-payment');
  if (proceedBtn) {
    proceedBtn.addEventListener('click', () => {
      // Optional: close cart modal
      const cartModal = document.getElementById('cart-modal');
      if (cartModal) cartModal.classList.remove('open');

      // Redirect to checkout page
      window.location.href = 'checkout.html';
    });
  }
});
