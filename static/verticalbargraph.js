$( document ).ready(function() {

    document.getElementById("createvbargraph").onclick = function(){
      makevbargraph();
    };

    function makevbargraph(){
        var ctxB = document.getElementById("vbargraph").getContext('2d');
        var name2 = document.getElementById("name").value.split(",");
        var value = document.getElementById("value").value.split(",");
        var colour = document.getElementById("colour").value.split(",");
        var bordercolour = document.getElementById("colour2").value.split(",");
        var borderwidth = document.getElementById("borderwidth").value;
        var title = document.getElementById("title").value;
        var ymin = document.getElementById("ymin").value;
        var ymax = document.getElementById("ymax").value;
        var step = document.getElementById("step").value;

        var myverticalbargraph = new Chart(ctxB, {
        type: 'bar',
        data: {
            labels: name2,
            datasets: [{
                data: value,
                backgroundColor: colour,
                borderColor: bordercolour,
                borderWidth: borderwidth,
                label: title,
            }]
        },
        options: {
        responsive: true,
        scales: {
            yAxes: [{
                ticks: {
                    min: parseFloat(ymin),
                    max: parseFloat(ymax),
                    stepSize: parseFloat(step)
                    },
                }],
            },
        }
    });
    // Background Colour
    backgroundcolour = document.getElementById("backgroundcolour").value;
    vbargraph.style.backgroundColor = backgroundcolour;
    }



    //onclick event for add colour button
  document.getElementById("addcolourbutton").onclick = function(){
    colourselector = document.getElementById("colourselector").value;
    colour = document.getElementById("colour").value;
    document.getElementById("colour").value = colour + "#" + colourselector + ",";
  };

  //onclick event for add colour button (2)
  document.getElementById("addcolourbutton2").onclick = function(){
    colourselector2 = document.getElementById("colourselector2").value;
    colour = document.getElementById("colour2").value;
    document.getElementById("colour2").value = colour + "#" + colourselector2 + ",";
  };




  // download function
    $('#vbgdownload').click(function(){
        html2canvas(document.querySelector('#vbargraph')).then(function(canvas) {

            console.log(canvas);
            saveAs(canvas.toDataURL(), 'mycanvas.png');
        });
    });

    function saveAs(uri, filename) {

    var link = document.createElement('a');

    if (typeof link.download === 'string') {

        link.href = uri;
        link.download = filename;

        //Firefox requires the link to be in the body
        document.body.appendChild(link);

        //simulate click
        link.click();

        //remove the link when done
        document.body.removeChild(link);

    } else {

        window.open(uri);

    }
    }




});