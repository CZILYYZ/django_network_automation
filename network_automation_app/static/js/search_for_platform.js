        $(document).ready(function() {
            // Filter devices by vendor
            $('#vendor').on('change', function() {
                var selectedVendor = $(this).val();
                if (selectedVendor) {
                    $('#device-table tbody tr').hide();
                    $('#device-table tbody tr[data-model="' + selectedVendor + '"]').show();
                } else {
                    $('#device-table tbody tr').show();
                }
                // Uncheck all devices when filter is applied
                $('#select-all').prop('checked', false);
                $('.device-select').prop('checked', false);
            });

            // Select/unselect all devices
            $('#select-all').on('change', function() {
                if ($(this).is(':checked')) {
                    $('.device-select').prop('checked', true);
                } else {
                    $('.device-select').prop('checked', false);
                }
            });
        });
