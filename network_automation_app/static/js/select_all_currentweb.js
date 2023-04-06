const selectAllCheckbox = document.getElementById('select-all');
const deviceCheckboxes = document.querySelectorAll('.device-select');

const selectDropdown = document.getElementById('vendor');
const deviceRows = document.querySelectorAll('.device-row');

selectDropdown.addEventListener('change', () => {
    const selectedVendor = selectDropdown.value;
    deviceRows.forEach((row) => {
        const deviceModel = row.getAttribute('data-model');
        if (selectedVendor === '' || selectedVendor === deviceModel) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    });
});

selectAllCheckbox.addEventListener('change', () => {
    deviceCheckboxes.forEach((checkbox) => {
        if (checkbox.closest('.device-row').style.display !== 'none' && selectAllCheckbox.checked) {
            checkbox.checked = true;
        } else {
            checkbox.checked = false;
        }
    });
});

deviceCheckboxes.forEach((checkbox) => {
    checkbox.addEventListener('change', () => {
        if (!checkbox.checked) {
            selectAllCheckbox.checked = false;
        }
    });
});