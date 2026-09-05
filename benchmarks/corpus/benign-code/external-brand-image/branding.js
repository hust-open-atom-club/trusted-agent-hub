const BRAND_IMAGE = "https://assets.vendor.invalid/brand/logo.png";

function renderBrandImage() {
  return `<img alt="Product logo" src="${BRAND_IMAGE}">`;
}

module.exports = { renderBrandImage };
