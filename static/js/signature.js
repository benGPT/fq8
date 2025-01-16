$(document).ready(function() {
    var canvas = document.getElementById('signatureCanvas');
    var ctx = canvas.getContext('2d');
    var drawing = false;
    var lastX, lastY;

    canvas.addEventListener('mousedown', startDrawing);
    canvas.addEventListener('mousemove', draw);
    canvas.addEventListener('mouseup', stopDrawing);
    canvas.addEventListener('mouseout', stopDrawing);

    function startDrawing(e) {
        drawing = true;
        [lastX, lastY] = [e.offsetX, e.offsetY];
    }

    function draw(e) {
        if (!drawing) return;
        ctx.beginPath();
        ctx.moveTo(lastX, lastY);
        ctx.lineTo(e.offsetX, e.offsetY);
        ctx.stroke();
        [lastX, lastY] = [e.offsetX, e.offsetY];
    }

    function stopDrawing() {
        drawing = false;
    }

    $('#clearSignature').click(function() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
    });

    $('#acceptPolicy').click(function() {
        var signatureData = canvas.toDataURL();
        $('#signatureData').val(signatureData);
        $('#policyForm').submit();
    });
});

