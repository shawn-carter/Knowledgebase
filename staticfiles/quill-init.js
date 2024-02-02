console.log("JavaScript Loaded");
document.addEventListener('DOMContentLoaded', (event) => {
    var quill = new Quill('#quillEditor', {
        theme: 'snow'
    });
});
