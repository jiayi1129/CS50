$( document ).ready(function() {

  document.getElementById("createpiechart").onclick = function(){
    makepiechart();
  };

    function makepiechart(){
    //pie
    var titlefontcolour = document.getElementById("titlefontcolour").value;
    var titlefontsize = document.getElementById("titlefontsize").value;
    var labelfontcolour = document.getElementById("labelfontcolour").value;
    var titleposition = document.getElementById("titleposition").value;
    var legendposition = document.getElementById("legendposition").value;
    var title = document.getElementById("title").value;
    var angle = document.getElementById("angleselector").value;
    var name2 = document.getElementById("name").value.split(",");
    var value = document.getElementById("value").value.split(",");
    var colour = document.getElementById("colour").value.split(",");
    var piechart = document.getElementById("piechart");
    var ctxP = document.getElementById("piechart").getContext('2d');
    var bordercolour = document.getElementById("colour2").value.split(",");
    var borderwidth = document.getElementById("borderwidth").value;
    var myPieChart = new Chart(ctxP, {
    type: 'doughnut',
    data: {
      labels: name2,
      datasets: [{
        data: value,
        backgroundColor: colour,
        borderColor: bordercolour,
        borderWidth: borderwidth
      }]
    },
    options: {
      rotation: angle/180 * Math.PI,
      responsive: true,
      title: {
        display: true,
        text: title,
        position: titleposition,
        fontSize: titlefontsize,
        fontColor: titlefontcolour
      },
      legend: {
        labels: {
          display: true,
          fontColor: labelfontcolour
      },
        display: true,
        position: legendposition
      }
    }
  });
  // Background Colour
  backgroundcolour = document.getElementById("backgroundcolour").value;
  piechart.style.backgroundColor = backgroundcolour;
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
    $('#piechartdownload').click(function(){
        html2canvas(document.querySelector('#piechart')).then(function(canvas) {

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