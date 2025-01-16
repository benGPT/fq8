$(document).ready(function() {
    // Form validation
    $('form').on('submit', function(e) {
        var requiredFields = $(this).find('[required]');
        var isValid = true;

        requiredFields.each(function() {
            if (!$(this).val()) {
                isValid = false;
                $(this).addClass('error');
            } else {
                $(this).removeClass('error');
            }
        });

        if (!isValid) {
            e.preventDefault();
            alert('Please fill in all required fields.');
        }
    });

    // Confirmation for delete actions
    $('.delete-btn').on('click', function(e) {
        if (!confirm('Are you sure you want to delete this item?')) {
            e.preventDefault();
        }
    });

    // Date range validation for leave application
    $('#end_date').on('change', function() {
        var startDate = new Date($('#start_date').val());
        var endDate = new Date($(this).val());

        if (endDate < startDate) {
            alert('End date cannot be earlier than start date.');
            $(this).val('');
        }
    });

    // File upload size validation
    $('input[type="file"]').on('change', function() {
        var maxSize = 5 * 1024 * 1024; // 5MB
        if (this.files[0].size > maxSize) {
            alert('File size exceeds 5MB. Please choose a smaller file.');
            $(this).val('');
        }
    });
});

